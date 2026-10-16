package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- what may be cached ----------------------------------------------------

// TestCacheSkipsRequestsWithCredentials covers the leak where a logged-in
// client's response is stored and then replayed to every other client that asks
// for the same path while the machine is asleep.
func TestCacheSkipsRequestsWithCredentials(t *testing.T) {
	backend := newCacheTestBackend(t, false)
	dir := t.TempDir()
	p, cs, _, _, _, _ := setupCacheProxy(t, backend, dir, []string{"/models"})

	for _, header := range [][2]string{
		{"Authorization", "Bearer super-secret"},
		{"Cookie", "session=abc123"},
	} {
		req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
		req.Header.Set(header[0], header[1])
		rec := httptest.NewRecorder()
		p.handleRequest(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s request: status = %d, want 200", header[0], rec.Code)
		}
	}

	// The capture runs when the proxy closes the body, so give it a moment
	// before insisting nothing landed.
	time.Sleep(300 * time.Millisecond)
	if _, ok := cs.Get("backend.test", "/models"); ok {
		t.Fatal("a response fetched with credentials must not be cached")
	}
	if files := listCacheFiles(t, dir); len(files) != 0 {
		t.Fatalf("cache files written for credentialed requests: %v", files)
	}
}

// TestCacheSkipsPrivateResponses covers the other half of the same leak: the
// response itself says it is not shareable.
func TestCacheSkipsPrivateResponses(t *testing.T) {
	cases := []struct {
		name    string
		headers http.Header
	}{
		{"Set-Cookie", http.Header{"Set-Cookie": []string{"session=abc123; Path=/"}}},
		{"Cache-Control private", http.Header{"Cache-Control": []string{"private"}}},
		{"Cache-Control no-store", http.Header{"Cache-Control": []string{"no-store"}}},
		{"Cache-Control no-cache", http.Header{"Cache-Control": []string{"no-cache, max-age=0"}}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.WriteHeader(http.StatusOK)
					return
				}
				for key, values := range tc.headers {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				io.WriteString(w, `{"data":[{"id":"model-a"}]}`)
			}))
			defer backend.Close()

			p, cs, _, _, _, _ := setupCacheProxy(t, backend, t.TempDir(), []string{"/models"})

			req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
			rec := httptest.NewRecorder()
			p.handleRequest(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			time.Sleep(300 * time.Millisecond)
			if _, ok := cs.Get("backend.test", "/models"); ok {
				t.Fatalf("a %s response must not be cached", tc.name)
			}
		})
	}
}

// TestSanitizeCachedHeadersDropsSetCookie checks the second guard: even if a
// Set-Cookie response reached Save, the header is not stored with the entry.
func TestSanitizeCachedHeadersDropsSetCookie(t *testing.T) {
	in := http.Header{
		"Set-Cookie":   []string{"session=abc123; Path=/"},
		"Content-Type": []string{"application/json"},
	}
	out := sanitizeCachedHeaders(in)

	if got := out.Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie must be dropped, got %v", got)
	}
	if got := out.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want it preserved", got)
	}
}

// --- capture completeness --------------------------------------------------

// truncatedReader hands out its chunks and then fails with a non-EOF error,
// standing in for an upstream reset or a client that hung up mid-copy.
type truncatedReader struct {
	chunks []string
	next   int
}

// Read yields the next chunk, or an error once they are exhausted.
func (r *truncatedReader) Read(p []byte) (int, error) {
	if r.next >= len(r.chunks) {
		return 0, errors.New("upstream reset")
	}
	n := copy(p, r.chunks[r.next])
	r.next++
	return n, nil
}

// TestCatchingBodySavesOnlyCompleteBodies pins the three capture rules: a body
// that ran to EOF is saved, one cut short by a read error is not, and one past
// the size limit is neither saved nor held in memory.
func TestCatchingBodySavesOnlyCompleteBodies(t *testing.T) {
	t.Run("complete body is saved", func(t *testing.T) {
		var saved []byte
		cb := &catchingBody{
			original: io.NopCloser(strings.NewReader("hello world")),
			buf:      &bytes.Buffer{},
			limit:    64,
			onDone:   func(body []byte) { saved = body },
		}
		if _, err := io.ReadAll(cb); err != nil {
			t.Fatalf("read: %v", err)
		}
		cb.Close()

		if string(saved) != "hello world" {
			t.Fatalf("saved = %q, want the whole body", saved)
		}
	})

	t.Run("body cut short by a read error is not saved", func(t *testing.T) {
		var saved []byte
		cb := &catchingBody{
			original: io.NopCloser(&truncatedReader{chunks: []string{"hel"}}),
			buf:      &bytes.Buffer{},
			limit:    64,
			onDone:   func(body []byte) { saved = body },
		}
		if _, err := io.ReadAll(cb); err == nil {
			t.Fatal("the read error must reach the caller")
		}
		cb.Close()

		if saved != nil {
			t.Fatalf("partial body %q must not be saved", saved)
		}
	})

	t.Run("oversized body is not saved and stops being buffered", func(t *testing.T) {
		var saved []byte
		const limit = 8
		cb := &catchingBody{
			original: io.NopCloser(strings.NewReader(strings.Repeat("a", 4096))),
			buf:      &bytes.Buffer{},
			limit:    limit,
			onDone:   func(body []byte) { saved = body },
		}
		if _, err := io.ReadAll(cb); err != nil {
			t.Fatalf("read: %v", err)
		}
		cb.Close()

		if saved != nil {
			t.Fatalf("a body over the limit (%d bytes) must not be saved", len(saved))
		}
		if !cb.overflow {
			t.Error("overflow must be flagged once the limit is passed")
		}
		if cb.buf != nil {
			t.Error("the buffer must be dropped once the body is over the limit")
		}
	})
}

// TestWarmMachineSkipsOversizedBody: io.LimitReader stops at the limit without
// an error, so reading exactly CacheMaxResponseSize bytes used to store a
// truncated body as a perfectly good 200.
func TestWarmMachineSkipsOversizedBody(t *testing.T) {
	body := strings.Repeat("x", 32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		io.WriteString(w, body)
	}))
	defer backend.Close()

	dir := t.TempDir()
	p, cs, _, _, _, machine := setupCacheProxy(t, backend, dir, []string{"/models"})
	cs.maxSize = 16
	p.config.CacheMaxResponseSize = 16

	p.warmMachine(machine)

	if _, ok := cs.Get("backend.test", "/models"); ok {
		t.Fatal("an oversized warm-up response must not be cached at all")
	}
	if files := listCacheFiles(t, dir); len(files) != 0 {
		t.Fatalf("oversized warm-up wrote cache files: %v", files)
	}
}

// --- cache configuration ---------------------------------------------------

// TestLoadConfigCacheRejectsNonPositiveDurations: warm_interval = "0s" reached
// time.NewTicker, which panics inside the warming goroutine and takes the whole
// proxy down at startup; a non-positive ttl expires every entry as it is saved.
func TestLoadConfigCacheRejectsNonPositiveDurations(t *testing.T) {
	load := func(t *testing.T, ttl, warmInterval string) error {
		t.Helper()
		src := `
port = ":9100"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[cache]
enabled = true
root_path = "` + filepath.Join(t.TempDir(), "cache") + `"
ttl = "` + ttl + `"
warm_interval = "` + warmInterval + `"

[[cache.routes]]
route = "llamacpp.home.test"
paths = ["/models"]

[[machines]]
name = "llamacpp"
mac_address = "A8:A1:59:40:D6:7D"
broadcast_ip = "192.168.50.255"
health_check = "http://192.168.50.2:8080/health"

[[routes]]
machine = "llamacpp"
hostname = "llamacpp.home.test"
destination = "http://192.168.50.2:8080"
`
		_, err := LoadConfig(writeTempConfig(t, src), RealClock{})
		return err
	}

	for _, tc := range []struct{ ttl, warmInterval, want string }{
		{"0s", "10m", "cache ttl"},
		{"-1h", "10m", "cache ttl"},
		{"24h", "0s", "warm_interval"},
		{"24h", "-5m", "warm_interval"},
	} {
		err := load(t, tc.ttl, tc.warmInterval)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ttl=%q warm_interval=%q: got %v, want an error mentioning %q",
				tc.ttl, tc.warmInterval, err, tc.want)
		}
	}

	if err := load(t, "24h", "10m"); err != nil {
		t.Errorf("positive durations must load, got: %v", err)
	}
}

// --- who gets served from cache --------------------------------------------

// TestCacheNotServedForHealthyMachineWithStaleHealth: the health cache going
// stale is not evidence the machine is down. Only a machine the health checker
// confirmed unhealthy may be answered from disk.
func TestCacheNotServedForHealthyMachineWithStaleHealth(t *testing.T) {
	var served int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		n := atomic.AddInt32(&served, 1)
		fmt.Fprintf(w, `{"data":[{"id":"live-%d"}]}`, n)
	}))
	defer backend.Close()

	p, cs, _, hc, _, machine := setupCacheProxy(t, backend, t.TempDir(), []string{"/models"})

	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)
	waitFor(t, 3*time.Second, "cache entry after the first proxied GET", func() bool {
		_, ok := cs.Get("backend.test", "/models")
		return ok
	})

	// Healthy, but with an entry old enough that healthCacheStatus calls it
	// stale. The machine is up: it must answer in person.
	hc.setResult(true)
	machine.mu.Lock()
	machine.IsHealthy = true
	machine.LastCheck = time.Now().Add(-time.Hour)
	machine.mu.Unlock()

	req2 := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec2 := httptest.NewRecorder()
	p.handleRequest(rec2, req2)

	body, _ := io.ReadAll(rec2.Result().Body)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the live machine", rec2.Code)
	}
	if !strings.Contains(string(body), "live-2") {
		t.Fatalf("got %q, want the live response; a stale health entry must not serve the cache", body)
	}
}

// TestCacheKeyIncludesQueryString: /models?filter=a and /models are different
// responses, so whichever was fetched last must not answer for the other.
func TestCacheKeyIncludesQueryString(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		fmt.Fprintf(w, `{"query":%q}`, r.URL.RawQuery)
	}))
	defer backend.Close()

	p, cs, wol, hc, _, machine := setupCacheProxy(t, backend, t.TempDir(), []string{"/models"})

	req := httptest.NewRequest("GET", "http://backend.test:9100/models?filter=a", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)
	waitFor(t, 3*time.Second, "cache entry for the filtered path", func() bool {
		_, ok := cs.Get("backend.test", "/models?filter=a")
		return ok
	})

	hc.setResult(false)
	setMachineHealth(machine, false)
	p.config.Timeout = 1 * time.Second

	// The unfiltered path was never fetched: the cache must not answer for it.
	req2 := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec2 := httptest.NewRecorder()
	p.handleRequest(rec2, req2)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /models while down: status=%d, want 503 rather than the filtered response", rec2.Code)
	}
	if wol.callCount() == 0 {
		t.Error("a cache miss must still attempt a wake")
	}

	// The exact URL that was fetched is served from cache.
	req3 := httptest.NewRequest("GET", "http://backend.test:9100/models?filter=a", nil)
	rec3 := httptest.NewRecorder()
	p.handleRequest(rec3, req3)
	body, _ := io.ReadAll(rec3.Result().Body)
	if rec3.Code != http.StatusOK || !strings.Contains(string(body), `filter=a`) {
		t.Fatalf("GET /models?filter=a while down: status=%d body=%q", rec3.Code, body)
	}
}

// --- on-disk writes --------------------------------------------------------

// TestWriteFileAtomicConcurrentWriters: the wake-triggered warm-up, the
// periodic warm-up and a proxied GET can all save the same key at once. A
// shared temp path let them interleave into a corrupt envelope before the
// rename, so each write gets its own temp file.
func TestWriteFileAtomicConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "entry.cache")

	const writers = 8
	payload := func(i int) []byte { return []byte(strings.Repeat(string(rune('A'+i)), 4096)) }

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := writeFileAtomic(filePath, payload(i)); err != nil {
				t.Errorf("writeFileAtomic: %v", err)
			}
		}(i)
	}
	wg.Wait()

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("published entry: %v", err)
	}
	whole := false
	for i := 0; i < writers; i++ {
		if bytes.Equal(data, payload(i)) {
			whole = true
			break
		}
	}
	if !whole {
		t.Fatalf("published entry is a mix of writers: %d bytes, first byte %q", len(data), data[:1])
	}

	leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}
