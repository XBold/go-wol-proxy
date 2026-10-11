package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- helpers ---------------------------------------------------------------

func newCacheTestBackend(t *testing.T, chunked bool) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/models", "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			if chunked {
				// Force a chunked response (no Content-Length) by flushing
				// partway through the body.
				if fl, ok := w.(http.Flusher); ok {
					io.WriteString(w, `{"data":[{"id":"model-`)
					fl.Flush()
					io.WriteString(w, `a"}]}`)
					return
				}
			}
			io.WriteString(w, `{"data":[{"id":"model-a"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(backend.Close)
	return backend
}

// setupCacheProxy wires a proxy with one machine ("llamacpp"), one HTTP route
// named after its hostname, and a cache rooted at cacheDir caching paths for
// that route.
func setupCacheProxy(t *testing.T, backend *httptest.Server, cacheDir string, paths []string) (*ProxyService, *CacheStore, *mockWOLSender, *mockHealthChecker, *recordingLogger, *Machine) {
	t.Helper()
	logger := &recordingLogger{}

	routeName := "backend.test"
	cs := NewCacheStore(cacheDir, 240*time.Hour, 10<<20, map[string][]string{routeName: paths}, logger)

	machine := &Machine{
		Name: "llamacpp",
		Config: &MachineConfig{
			MacAddress:  "A8:A1:59:40:D6:7D",
			BroadcastIP: "127.0.0.1",
			WolPort:     9,
			HealthCheck: backend.URL + "/health",
		},
		IsHealthy:    true,
		LastCheck:    time.Now(),
		LastActivity: time.Now(),
	}

	route := &Route{
		Name:        routeName,
		Machine:     machine,
		Hostname:    "backend.test",
		Destination: backend.URL,
		HealthCheck: backend.URL + "/health",
		IsReady:     true,
		LastCheck:   time.Now(),
	}

	cfg := &ProxyConfig{
		Port:                  "127.0.0.1:0",
		Timeout:               10 * time.Second,
		PollInterval:          1 * time.Second,
		ResponseHeaderTimeout: time.Minute,
		HealthCheckInterval:   30 * time.Second,
		HealthCacheDuration:   10 * time.Second,
		Machines:              map[string]*Machine{"llamacpp": machine},
		Routes:                []*Route{route},
		RoutesByHostname:      map[string]*Route{"backend.test": route},
		CacheEnabled:          true,
		CacheRootPath:         cacheDir,
		CacheTTL:              240 * time.Hour,
		CacheMaxResponseSize:  10 << 20,
		CacheWarmInterval:     10 * time.Minute,
		CacheRoutes:           map[string][]string{routeName: paths},
	}

	wol := newMockWOLSender()
	hc := &mockHealthChecker{}
	hc.setResult(true)
	p := NewProxyService(cfg, hc, wol, newMockSSHExecutor(), logger, RealClock{}, cs)
	return p, cs, wol, hc, logger, machine
}

func setMachineHealth(machine *Machine, healthy bool) {
	machine.mu.Lock()
	machine.IsHealthy = healthy
	machine.LastCheck = time.Now()
	machine.mu.Unlock()
}

func listCacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	entries, err := os.ReadDir(filepath.Join(dir, "backend.test"))
	if err != nil {
		return out
	}
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// --- config ----------------------------------------------------------------

func TestLoadConfigCache(t *testing.T) {
	const toml = `
port = ":9100"
timeout = "1m"
poll_interval = "5s"
response_header_timeout = "10m"
health_check_interval = "30s"
health_cache_duration = "10s"

[cache]
enabled = true
root_path = "/app/cache"
ttl = "240h"
max_response_size_bytes = 10485760
warm_interval = "10m"

[[cache.routes]]
route = "llamacpp.home.test"
paths = ["/v1/models", "/models"]

[[machines]]
name = "llamacpp"
mac_address = "A8:A1:59:40:D6:7D"
broadcast_ip = "192.168.50.255"
wol_port = 9
health_check = "http://192.168.50.2:8080/health"

[[routes]]
machine = "llamacpp"
hostname = "llamacpp.home.test"
destination = "http://192.168.50.2:8080"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path, RealClock{})
	if err != nil {
		t.Fatalf("config failed to load: %v", err)
	}
	if !cfg.CacheEnabled {
		t.Error("cache should be enabled")
	}
	if got := cfg.CacheRootPath; got != "/app/cache" {
		t.Errorf("CacheRootPath = %q, want /app/cache", got)
	}
	if got := cfg.CacheTTL; got != 240*time.Hour {
		t.Errorf("CacheTTL = %v, want 240h", got)
	}
	if got := cfg.CacheMaxResponseSize; got != 10485760 {
		t.Errorf("CacheMaxResponseSize = %d, want 10485760", got)
	}
	if got := cfg.CacheWarmInterval; got != 10*time.Minute {
		t.Errorf("CacheWarmInterval = %v, want 10m", got)
	}
	paths := cfg.CacheRoutes["llamacpp.home.test"]
	if len(paths) != 2 || paths[0] != "/v1/models" || paths[1] != "/models" {
		t.Fatalf("CacheRoutes[llamacpp.home.test] = %v, want [/v1/models /models]", paths)
	}
}

func TestLoadConfigCacheDefaults(t *testing.T) {
	const toml = `
port = ":9100"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[cache]
enabled = true

[[machines]]
name = "nas"
mac_address = "AA:BB:CC:DD:EE:FF"
broadcast_ip = "10.0.0.255"
health_check = "tcp://nas.local:22"

[[routes]]
machine = "nas"
hostname = "nas.home.test"
destination = "http://nas.local"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path, RealClock{})
	if err != nil {
		t.Fatalf("config failed to load: %v", err)
	}
	if !cfg.CacheEnabled {
		t.Fatal("cache should be enabled")
	}
	if got := cfg.CacheRootPath; got != "./cache" {
		t.Errorf("CacheRootPath = %q, want ./cache", got)
	}
	if got := cfg.CacheTTL; got != 24*time.Hour {
		t.Errorf("CacheTTL = %v, want 24h", got)
	}
	if got := cfg.CacheMaxResponseSize; got != 10*1024*1024 {
		t.Errorf("CacheMaxResponseSize = %d, want 10485760", got)
	}
	if got := cfg.CacheWarmInterval; got != 30*time.Minute {
		t.Errorf("CacheWarmInterval = %v, want 30m", got)
	}
}

func TestLoadConfigCacheRejectsUnknownRoute(t *testing.T) {
	const toml = `
port = ":9100"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[cache]
enabled = true

[[cache.routes]]
route = "typo.home.test"
paths = ["/models"]

[[machines]]
name = "nas"
mac_address = "AA:BB:CC:DD:EE:FF"
broadcast_ip = "10.0.0.255"
health_check = "tcp://nas.local:22"

[[routes]]
machine = "nas"
hostname = "nas.home.test"
destination = "http://nas.local"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(path, RealClock{}); err == nil ||
		!strings.Contains(err.Error(), `unknown route "typo.home.test"`) {
		t.Errorf("cache naming a non-existent route must be rejected, got: %v", err)
	}
}

func TestLoadConfigCacheRejectsTCPRoute(t *testing.T) {
	const toml = `
port = ":9100"
timeout = "1m"
poll_interval = "5s"
health_check_interval = "30s"
health_cache_duration = "10s"

[cache]
enabled = true

[[cache.routes]]
route = ":2222"
paths = ["/models"]

[[machines]]
name = "nas"
mac_address = "AA:BB:CC:DD:EE:FF"
broadcast_ip = "10.0.0.255"
health_check = "tcp://nas.local:22"

[[routes]]
machine = "nas"
listen_port = 2222
destination = "nas.local:22"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(path, RealClock{}); err == nil ||
		!strings.Contains(err.Error(), "only HTTP routes can be cached") {
		t.Errorf("cache naming a TCP route must be rejected, got: %v", err)
	}
}

// --- serving ---------------------------------------------------------------

// Proxying a GET /models while the machine is healthy must populate the cache
// on disk (ModifyResponse body capture -> Save). Once the machine is down the
// cached response must be served without sending a single WOL packet.
func TestCachePopulatedViaProxiedResponse(t *testing.T) {
	backend := newCacheTestBackend(t, false)
	p, cs, wol, hc, _, machine := setupCacheProxy(t, backend, t.TempDir(), []string{"/models"})

	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// The proxied body is cached when the proxy closes it, which can lag the
	// recorder by a fraction of a second: poll briefly.
	waitFor(t, 3*time.Second, "cache entry after proxied GET", func() bool {
		_, ok := cs.Get("backend.test", "/models")
		return ok
	})

	// Machine goes down: the cached response must be served, no WOL.
	hc.setResult(false)
	setMachineHealth(machine, false)

	req2 := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec2 := httptest.NewRecorder()
	p.handleRequest(rec2, req2)

	body, _ := io.ReadAll(rec2.Result().Body)
	if rec2.Code != 200 || !strings.Contains(string(body), "model-a") {
		t.Fatalf("cached response wrong: status=%d body=%q", rec2.Code, body)
	}
	if got := wol.callCount(); got != 0 {
		t.Errorf("WOL sent %d time(s) although the cache could answer", got)
	}
}

// A chunked upstream response (no Content-Length, like many small JSON
// servers send) must be cached and replayed in full.
func TestCachedChunkedResponseServedCorrectly(t *testing.T) {
	backend := newCacheTestBackend(t, true)
	p, cs, _, hc, _, machine := setupCacheProxy(t, backend, t.TempDir(), []string{"/models"})

	// Populate while healthy.
	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	waitFor(t, 3*time.Second, "chunked response cached", func() bool {
		_, ok := cs.Get("backend.test", "/models")
		return ok
	})

	// Serve from cache while down.
	hc.setResult(false)
	setMachineHealth(machine, false)

	req2 := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec2 := httptest.NewRecorder()
	p.handleRequest(rec2, req2)

	body, _ := io.ReadAll(rec2.Result().Body)
	if rec2.Code != 200 || string(body) != `{"data":[{"id":"model-a"}]}` {
		t.Fatalf("served chunked-cache response wrong: status=%d body=%q", rec2.Code, body)
	}
}

// warmMachine must (re)populate the cache for all configured paths of every
// HTTP route pointing at the machine.
func TestWarmMachinePopulates(t *testing.T) {
	backend := newCacheTestBackend(t, false)
	p, cs, _, _, _, machine := setupCacheProxy(t, backend, t.TempDir(), []string{"/v1/models", "/models"})

	p.warmMachine(machine)

	files := listCacheFiles(t, cs.rootPath)
	t.Logf("cache files after warm: %v", files)
	// Two paths -> one single-file entry each.
	if len(files) != 2 {
		t.Fatalf("expected 2 cache entries, got %v", files)
	}
	if _, ok := cs.Get("backend.test", "/models"); !ok {
		t.Error("/models not cached after warm")
	}
	if _, ok := cs.Get("backend.test", "/v1/models"); !ok {
		t.Error("/v1/models not cached after warm")
	}
}

// Entries written by older versions (body file + ".meta" sidecar) must keep
// working after the upgrade, so an upgraded container does not start waking
// the machine for responses that are already cached on disk.
func TestLegacyCacheEntriesStillLoadable(t *testing.T) {
	backend := newCacheTestBackend(t, false)
	cacheDir := t.TempDir()
	logger := &recordingLogger{}

	// Seed a legacy two-file entry before the store starts so that loadAll
	// has to discover it. The key must be computed the same way the
	// production code does: from the path.Clean-ed path.
	{
		probe := NewCacheStore(cacheDir, 240*time.Hour, 10<<20, map[string][]string{"backend.test": {"/models"}}, logger)
		cleaned := path.Clean("/models")
		k := probe.key("backend.test", cleaned)
		dir := filepath.Join(cacheDir, "backend.test")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"data":[{"id":"legacy-model"}]}`)
		if err := os.WriteFile(filepath.Join(dir, k+".cache"), body, 0644); err != nil {
			t.Fatal(err)
		}
		pathJSON, err := json.Marshal(cleaned)
		if err != nil {
			t.Fatal(err)
		}
		meta := `{"status_code":200,"headers":{"Content-Type":["application/json"]},"timestamp":"` +
			time.Now().Add(-time.Hour).Format(time.RFC3339) + `","path":` + string(pathJSON) + `}`
		if err := os.WriteFile(filepath.Join(dir, k+".cache.meta"), []byte(meta), 0644); err != nil {
			t.Fatal(err)
		}
	}

	p, _, wol, hc, _, machine := setupCacheProxy(t, backend, cacheDir, []string{"/models"})

	// Machine down: the legacy entry must be served from the cache, no WOL.
	hc.setResult(false)
	setMachineHealth(machine, false)

	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != 200 || !strings.Contains(string(body), "legacy-model") {
		t.Fatalf("legacy entry not served: status=%d body=%q", rec.Code, body)
	}
	if got := wol.callCount(); got != 0 {
		t.Errorf("WOL sent for a request a legacy cache entry could serve (sent=%d)", got)
	}
}

// --- CacheStore internals ---------------------------------------------------

// sanitizeCachedHeaders must drop framing/hop-by-hop headers so a cached
// response is re-framed correctly when served from disk.
func TestSanitizeCachedHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", "42")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Connection", "keep-alive")
	h.Set("X-Custom", "kept")

	out := sanitizeCachedHeaders(h)
	for _, k := range []string{"Content-Length", "Transfer-Encoding", "Connection"} {
		if _, ok := out[k]; ok {
			t.Errorf("%s must be stripped, got %v", k, out[k])
		}
	}
	if out.Get("Content-Type") != "application/json" || out.Get("X-Custom") != "kept" {
		t.Errorf("normal headers must be kept: %v", out)
	}
}

// Saving an unchanged body must skip the disk write while the entry is still
// on disk, but must write again once the file is gone: skipping the write on
// an unchanged body whose file vanished (TTL expiry, manual cleanup) would
// leave the cache empty forever for static responses, sending WOL on every
// offline request.
func TestCacheSaveSkipsUnchangedButRewritesMissingFile(t *testing.T) {
	dir := t.TempDir()
	cs := NewCacheStore(dir, 240*time.Hour, 10<<20, map[string][]string{"r": {"/p"}}, &recordingLogger{})

	body := []byte("same")
	cs.Save("r", "/p", 200, http.Header{"Content-Type": []string{"text/plain"}}, body)

	first, err := os.Stat(cs.cacheFilePath("r", "/p"))
	if err != nil {
		t.Fatal(err)
	}

	cs.Save("r", "/p", 200, http.Header{"Content-Type": []string{"text/plain"}}, body)
	second, err := os.Stat(cs.cacheFilePath("r", "/p"))
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Error("unchanged body must not rewrite the cache file")
	}

	if err := os.Remove(cs.cacheFilePath("r", "/p")); err != nil {
		t.Fatal(err)
	}
	cs.Save("r", "/p", 200, http.Header{"Content-Type": []string{"text/plain"}}, body)
	if _, ok := cs.Get("r", "/p"); !ok {
		t.Error("unchanged body must be rewritten after the cache file disappeared")
	}
}

// Responses larger than the configured maximum must not be cached.
func TestCacheRejectsOversizedResponse(t *testing.T) {
	dir := t.TempDir()
	cs := NewCacheStore(dir, 240*time.Hour, 10, map[string][]string{"r": {"/p"}}, &recordingLogger{})

	cs.Save("r", "/p", 200, http.Header{}, []byte(strings.Repeat("x", 11)))
	if _, ok := cs.Get("r", "/p"); ok {
		t.Error("oversized response must not be cached")
	}
}

// Cleanup must drop expired entries from memory and from disk.
func TestCacheCleanupRemovesExpired(t *testing.T) {
	dir := t.TempDir()
	cs := NewCacheStore(dir, time.Millisecond, 10<<20, map[string][]string{"r": {"/p"}}, &recordingLogger{})

	cs.Save("r", "/p", 200, http.Header{}, []byte("body"))
	time.Sleep(5 * time.Millisecond)

	cs.Cleanup()

	if _, ok := cs.Get("r", "/p"); ok {
		t.Error("expired entry must be gone from memory")
	}
	if _, err := os.Stat(cs.cacheFilePath("r", "/p")); !os.IsNotExist(err) {
		t.Error("expired entry must be removed from disk")
	}
}

// A "/*" pattern must warm every concrete path already cached under its
// prefix, while an exact pattern warms only itself.
func TestGetCachedPathsForRouteWildcard(t *testing.T) {
	cs := NewCacheStore(t.TempDir(), 240*time.Hour, 10<<20,
		map[string][]string{"r": {"/assets/*", "/docs"}}, &recordingLogger{})

	cs.Save("r", "/assets/a.css", 200, http.Header{}, []byte("a"))
	cs.Save("r", "/assets/b.js", 200, http.Header{}, []byte("b"))
	cs.Save("r", "/docs", 200, http.Header{}, []byte("d"))

	got := cs.GetCachedPathsForRoute("r")
	want := map[string]bool{"/docs": true, "/assets/a.css": true, "/assets/b.js": true}
	if len(got) != len(want) {
		t.Fatalf("GetCachedPathsForRoute = %v, want %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("GetCachedPathsForRoute = %v, want %v", got, want)
		}
	}
}

// The cache must not answer non-GET requests: a cached body replayed for a
// POST would hide the write from the machine.
func TestCacheDoesNotServeNonGET(t *testing.T) {
	backend := newCacheTestBackend(t, false)
	p, cs, wol, hc, _, machine := setupCacheProxy(t, backend, t.TempDir(), []string{"/models"})

	// Populate the cache via a healthy GET.
	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)
	waitFor(t, 3*time.Second, "cache entry after proxied GET", func() bool {
		_, ok := cs.Get("backend.test", "/models")
		return ok
	})

	hc.setResult(false)
	setMachineHealth(machine, false)

	// Shorten the wake so the 503 arrives quickly: the point of the test is
	// that the cache does not answer the POST, not the wake itself.
	p.config.Timeout = 1 * time.Second
	p.config.PollInterval = 200 * time.Millisecond

	req2 := httptest.NewRequest("POST", "http://backend.test:9100/models", strings.NewReader("{}"))
	rec2 := httptest.NewRecorder()
	p.handleRequest(rec2, req2)

	// The machine is down and the health check fails: the wake must time out
	// with a 503 rather than being answered from the cache.
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST while down: status=%d, want 503 (cache must not answer writes)", rec2.Code)
	}
	if wol.callCount() == 0 {
		t.Error("POST while down must attempt a wake")
	}
}

// A cached response must be served with its stored headers and status, and
// must not leak the wake path: this is the exact scenario from the upstream
// issue - static assets served immediately while the target is asleep.
func TestCacheServePreservesStatusAndHeaders(t *testing.T) {
	dir := t.TempDir()
	cs := NewCacheStore(dir, 240*time.Hour, 10<<20, map[string][]string{"r": {"/p"}}, &recordingLogger{})
	cs.Save("r", "/p", 200, http.Header{"Content-Type": []string{"application/json"}, "Cache-Control": []string{"max-age=60"}}, []byte(`{"ok":true}`))

	resp, ok := cs.Get("r", "/p")
	if !ok {
		t.Fatal("entry not found")
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "max-age=60" {
		t.Errorf("Cache-Control = %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", body)
	}
}
