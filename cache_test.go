package main

import (
	"context"
	"encoding/json"
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

// --- mocks ----------------------------------------------------------------

type mockWOL struct{ sent atomic.Int32 }

func (m *mockWOL) SendWOL(macAddr, broadcastIP string, port int) error {
	m.sent.Add(1)
	return nil
}

type mockHealth struct {
	healthy atomic.Bool
	checks  atomic.Int32
}

func (m *mockHealth) Check(ctx context.Context, endpoint string, source string) bool {
	m.checks.Add(1)
	return m.healthy.Load()
}
func (m *mockHealth) StartBackgroundChecks(ctx context.Context, targets map[string]*TargetState, interval time.Duration) {
}
func (m *mockHealth) WaitForInitialChecks(ctx context.Context) error { return nil }
func (m *mockHealth) CloseIdleConnections()                          {}

type mockSSH struct{}

func (m *mockSSH) ExecuteCommand(host, user, keyPath, knownHosts, command string) error {
	return nil
}

type recLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recLogger) log(level, msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, level+" "+fmt.Sprintf(msg, args...))
}
func (l *recLogger) Info(msg string, args ...interface{})  { l.log("INFO  ", msg, args...) }
func (l *recLogger) Error(msg string, args ...interface{}) { l.log("ERROR ", msg, args...) }
func (l *recLogger) Debug(msg string, args ...interface{}) { l.log("DEBUG ", msg, args...) }

func (l *recLogger) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *recLogger) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(strings.Join(l.lines, "\n"), substr)
}

// --- helpers ---------------------------------------------------------------

func newTestBackend(t *testing.T, chunked bool) *httptest.Server {
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

func setupProxyWithPaths(t *testing.T, backend *httptest.Server, paths []string, startupTime time.Duration) (*ProxyService, *CacheStore, *mockWOL, *mockHealth, *recLogger, *TargetState) {
	t.Helper()
	return setupProxy(t, backend, t.TempDir(), paths, startupTime)
}

func setupProxy(t *testing.T, backend *httptest.Server, cacheDir string, paths []string, startupTime time.Duration) (*ProxyService, *CacheStore, *mockWOL, *mockHealth, *recLogger, *TargetState) {
	t.Helper()
	logger := &recLogger{}

	cs := NewCacheStore(cacheDir, 240*time.Hour, 10<<20, map[string][]string{"llamacpp": paths}, logger)

	target := &Target{
		Name:           "llamacpp",
		Hostname:       "backend.test",
		Destination:    backend.URL,
		HealthEndpoint: backend.URL + "/health",
		MacAddress:     "A8:A1:59:40:D6:7D",
		BroadcastIP:    "127.0.0.1",
		WolPort:        9,
		WOLBurstCount:  1,
	}
	ts := &TargetState{Target: target, IsHealthy: true, LastCheck: time.Now()}

	cfg := &ProxyConfig{
		Port:                  "127.0.0.1:0",
		Timeout:               10 * time.Second,
		StartupTime:           startupTime,
		ResponseHeaderTimeout: time.Minute,
		HealthCheckInterval:   30 * time.Second,
		HealthCacheDuration:   10 * time.Second,
		LogLevel:              "debug",
		Targets:               map[string]*TargetState{"llamacpp": ts},
		HostnameMap:           map[string]string{"backend.test": "llamacpp"},
		CacheEnabled:          true,
		CacheRootPath:         cacheDir,
		CacheTTL:              240 * time.Hour,
		CacheMaxResponseSize:  10 << 20,
		CacheWarmInterval:     10 * time.Minute,
		CachePaths:            map[string][]string{"llamacpp": paths},
	}

	wol := &mockWOL{}
	hc := &mockHealth{}
	hc.healthy.Store(true)
	p := NewProxyService(cfg, hc, wol, &mockSSH{}, logger, cs)
	return p, cs, wol, hc, logger, ts
}

func (ts *TargetState) setHealth(healthy bool) {
	ts.mu.Lock()
	ts.IsHealthy = healthy
	ts.LastCheck = time.Now()
	ts.mu.Unlock()
}

func listCacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	entries, err := os.ReadDir(filepath.Join(dir, "llamacpp"))
	if err != nil {
		return out
	}
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// getFrom issues GET url with the Host header the proxy expects and reads the
// whole response. It returns an error instead of calling t.Fatal so it can be
// called from helper goroutines.
func getFrom(t *testing.T, client *http.Client, url string, timeout time.Duration) (int, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = "backend.test:9100"
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

// --- tests -----------------------------------------------------------------

// The exact config from the bug report must load with the cache target paths
// intact (rules out a config-parsing problem for the /models cache).
func TestLoadConfigFromBugReport(t *testing.T) {
	const toml = `
port = ":9100"
timeout = "1m"
startup_time = "30s"
response_header_timeout = "10m"
health_check_interval = "30s"
health_cache_duration = "10s"
log_level = "info"

[cache]
enabled = true
root_path = "/app/cache"
ttl = "240h"
max_response_size_bytes = 10485760
warm_interval = "10m"

[[cache.targets]]
target = "llamacpp"
paths = ["/v1/models", "/models"]

[[targets]]
name = "llamacpp"
hostname = "192.168.50.80"
destination = "http://192.168.50.2:8080"
health_endpoint = "http://192.168.50.2:8080/health"
mac_address = "A8:A1:59:40:D6:7D"
broadcast_ip = "192.168.50.255"
wol_port = 9
wol_burst_count = 1
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
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
	paths := cfg.CachePaths["llamacpp"]
	if len(paths) != 2 || paths[0] != "/v1/models" || paths[1] != "/models" {
		t.Fatalf("CachePaths[llamacpp] = %v, want [/v1/models /models]", paths)
	}
	ts, ok := cfg.Targets["llamacpp"]
	if !ok {
		t.Fatal("target llamacpp missing")
	}
	if ts.Target.WolPort != 9 || ts.Target.WOLBurstCount != 1 {
		t.Errorf("WOL config wrong: port=%d burst=%d", ts.Target.WolPort, ts.Target.WOLBurstCount)
	}
	if got := cfg.HostnameMap["192.168.50.80"]; got != "llamacpp" {
		t.Errorf("HostnameMap[192.168.50.80] = %q, want llamacpp", got)
	}
	if cfg.Timeout != time.Minute || cfg.StartupTime != 30*time.Second {
		t.Errorf("durations wrong: timeout=%v startup=%v", cfg.Timeout, cfg.StartupTime)
	}
	if cfg.HealthCacheDuration != 10*time.Second || cfg.HealthCheckInterval != 30*time.Second {
		t.Errorf("health durations wrong: cache=%v interval=%v", cfg.HealthCacheDuration, cfg.HealthCheckInterval)
	}
}

// Proxying a GET /models while the target is healthy must populate the cache
// on disk (ModifyResponse body capture -> Save).
func TestCachePopulatedViaProxiedResponse(t *testing.T) {
	backend := newTestBackend(t, false)
	p, cs, _, hc, _, _ := setupProxyWithPaths(t, backend, []string{"/models"}, time.Second)

	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if _, ok := cs.Get("llamacpp", "/models"); !ok {
		t.Fatalf("GET /models not cached after proxying it (files: %v)", listCacheFiles(t, cs.rootPath))
	}

	// Machine goes down: the cached response must be served, no WOL.
	hc.healthy.Store(false)
	p.config.Targets["llamacpp"].setHealth(false)

	wol := p.wolSender.(*mockWOL)
	req2 := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec2 := httptest.NewRecorder()
	p.handleRequest(rec2, req2)

	body, _ := io.ReadAll(rec2.Result().Body)
	if rec2.Code != 200 || !strings.Contains(string(body), "model-a") {
		t.Fatalf("cached response wrong: status=%d body=%q", rec2.Code, body)
	}
	if got := wol.sent.Load(); got != 0 {
		t.Errorf("WOL sent %d time(s) although the cache could answer", got)
	}
}

// warmCache must (re)populate the cache for all configured paths.
func TestWarmCachePopulates(t *testing.T) {
	backend := newTestBackend(t, false)
	p, cs, _, _, _, _ := setupProxyWithPaths(t, backend, []string{"/v1/models", "/models"}, time.Second)

	p.warmCache("llamacpp")

	files := listCacheFiles(t, cs.rootPath)
	t.Logf("cache files after warm: %v", files)
	// Two paths -> one single-file entry each.
	if len(files) != 2 {
		t.Fatalf("expected 2 cache entries, got %v", files)
	}
	if _, ok := cs.Get("llamacpp", "/models"); !ok {
		t.Error("/models not cached after warm")
	}
	if _, ok := cs.Get("llamacpp", "/v1/models"); !ok {
		t.Error("/v1/models not cached after warm")
	}
}

// A chunked upstream response (no Content-Length, like many small JSON
// servers send) must be cached and replayed in full.
func TestCachedChunkedResponseServedCorrectly(t *testing.T) {
	backend := newTestBackend(t, true)
	p, cs, _, hc, _, ts := setupProxyWithPaths(t, backend, []string{"/models"}, time.Second)

	// Populate while healthy.
	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if _, ok := cs.Get("llamacpp", "/models"); !ok {
		t.Fatal("chunked response was not cached")
	}

	// Serve from cache while down.
	hc.healthy.Store(false)
	ts.setHealth(false)

	req2 := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec2 := httptest.NewRecorder()
	p.handleRequest(rec2, req2)

	body, _ := io.ReadAll(rec2.Result().Body)
	if rec2.Code != 200 || string(body) != `{"data":[{"id":"model-a"}]}` {
		t.Fatalf("served chunked-cache response wrong: status=%d body=%q", rec2.Code, body)
	}
}

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

// Entries written by older versions (body file + ".meta" sidecar) must keep
// working after the upgrade, so an upgraded container does not start waking
// the machine for responses that are already cached on disk.
func TestLegacyCacheEntriesStillLoadable(t *testing.T) {
	backend := newTestBackend(t, false)
	cacheDir := t.TempDir()
	logger := &recLogger{}

	// Seed a legacy two-file entry before the store starts so that loadAll
	// has to discover it. The key must be computed the same way the
	// production code does: from the filepath.Clean-ed path.
	{
		probe := NewCacheStore(cacheDir, 240*time.Hour, 10<<20, map[string][]string{"llamacpp": {"/models"}}, logger)
		cleaned := filepath.Clean("/models")
		k := probe.key("llamacpp", cleaned)
		dir := filepath.Join(cacheDir, "llamacpp")
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

	p, _, wol, hc, _, ts := setupProxy(t, backend, cacheDir, []string{"/models"}, time.Second)

	// Target down: the legacy entry must be served from the cache, no WOL.
	hc.healthy.Store(false)
	ts.setHealth(false)

	req := httptest.NewRequest("GET", "http://backend.test:9100/models", nil)
	rec := httptest.NewRecorder()
	p.handleRequest(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != 200 || !strings.Contains(string(body), "legacy-model") {
		t.Fatalf("legacy entry not served: status=%d body=%q", rec.Code, body)
	}
	if got := wol.sent.Load(); got != 0 {
		t.Errorf("WOL sent for a request a legacy cache entry could serve (sent=%d)", got)
	}
}

// The global timeout is optional (defaults to 120s) and per-target
// wake_timeout / wake_health_check_interval must parse into the right maps
// without leaking into other targets.
func TestLoadConfigWakeOptions(t *testing.T) {
	const toml = `
port = ":9100"
health_check_interval = "30s"
health_cache_duration = "10s"

[[targets]]
name = "llamacpp"
hostname = "192.168.50.80"
destination = "http://192.168.50.2:8080"
health_endpoint = "http://192.168.50.2:8080/health"
mac_address = "A8:A1:59:40:D6:7D"
broadcast_ip = "192.168.50.255"
wake_timeout = "120s"
wake_health_check_interval = "2s"

[[targets]]
name = "other"
hostname = "other.host.com"
destination = "http://other.local"
health_endpoint = "http://other.local/health"
mac_address = "AA:BB:CC:DD:EE:FF"
broadcast_ip = "10.0.0.255"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("config failed to load: %v", err)
	}
	if got := cfg.Timeout; got != 120*time.Second {
		t.Errorf("default Timeout = %v, want 120s", got)
	}
	if got := cfg.WakeTimeouts["llamacpp"]; got != 120*time.Second {
		t.Errorf("WakeTimeouts[llamacpp] = %v, want 120s", got)
	}
	if got := cfg.WakeCheckIntervals["llamacpp"]; got != 2*time.Second {
		t.Errorf("WakeCheckIntervals[llamacpp] = %v, want 2s", got)
	}
	if _, ok := cfg.WakeTimeouts["other"]; ok {
		t.Error("target without wake_timeout must not be in WakeTimeouts")
	}
	if _, ok := cfg.WakeCheckIntervals["other"]; ok {
		t.Error("target without wake_health_check_interval must not be in WakeCheckIntervals")
	}
}

// startup_time must stay below the *effective* wake timeout: both the global
// default (no timeout key) and a per-target wake_timeout.
func TestLoadConfigWakeValidation(t *testing.T) {
	const base = `
port = ":9100"
health_check_interval = "30s"
health_cache_duration = "10s"
%s
[[targets]]
name = "llamacpp"
hostname = "192.168.50.80"
destination = "http://192.168.50.2:8080"
health_endpoint = "http://192.168.50.2:8080/health"
mac_address = "A8:A1:59:40:D6:7D"
broadcast_ip = "192.168.50.255"
%s
`
	load := func(t *testing.T, extra, targetExtra string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(fmt.Sprintf(base, extra, targetExtra)), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path)
		return err
	}

	if err := load(t, `startup_time = "150s"`, ""); err == nil ||
		!strings.Contains(err.Error(), "must be less than timeout") {
		t.Errorf("startup_time above the default timeout must be rejected, got: %v", err)
	}
	if err := load(t, `startup_time = "90s"`, `wake_timeout = "30s"`); err == nil ||
		!strings.Contains(err.Error(), "must be less than wake_timeout") {
		t.Errorf("startup_time above a per-target wake_timeout must be rejected, got: %v", err)
	}
}

// The server's read/write timeouts must default to 0 (no timeout) so long SSE
// streams are not killed: a positive default would terminate them. "0" and an
// absent key must both give 0, positive values must parse, and invalid or
// negative values must be rejected (a negative http.Server timeout is an
// already-passed deadline and would fail every request instantly).
func TestLoadConfigServerTimeouts(t *testing.T) {
	const base = `
port = ":9100"
health_check_interval = "30s"
health_cache_duration = "10s"
%s
[[targets]]
name = "llamacpp"
hostname = "192.168.50.80"
destination = "http://192.168.50.2:8080"
health_endpoint = "http://192.168.50.2:8080/health"
mac_address = "A8:A1:59:40:D6:7D"
broadcast_ip = "192.168.50.255"
`
	load := func(t *testing.T, extra string) (*ProxyConfig, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(fmt.Sprintf(base, extra)), 0644); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(path)
	}

	// Absent keys -> 0 (no timeout)
	cfg, err := load(t, "")
	if err != nil {
		t.Fatalf("config without timeouts must load: %v", err)
	}
	if cfg.ResponseTimeout != 0 || cfg.RequestTimeout != 0 {
		t.Errorf("unset timeouts must be 0 (no timeout), got response=%v request=%v",
			cfg.ResponseTimeout, cfg.RequestTimeout)
	}

	// Explicit "0" -> 0 (no timeout)
	cfg, err = load(t, `response_timeout = "0"
request_timeout = "0"`)
	if err != nil {
		t.Fatalf("explicit 0 timeouts must load: %v", err)
	}
	if cfg.ResponseTimeout != 0 || cfg.RequestTimeout != 0 {
		t.Errorf("explicit 0 timeouts must stay 0, got response=%v request=%v",
			cfg.ResponseTimeout, cfg.RequestTimeout)
	}

	// Positive values parse
	cfg, err = load(t, `response_timeout = "10m"
request_timeout = "30s"`)
	if err != nil {
		t.Fatalf("positive timeouts must load: %v", err)
	}
	if cfg.ResponseTimeout != 10*time.Minute || cfg.RequestTimeout != 30*time.Second {
		t.Errorf("positive timeouts wrong: response=%v request=%v",
			cfg.ResponseTimeout, cfg.RequestTimeout)
	}

	// Invalid values rejected
	if _, err := load(t, `response_timeout = "10 bananas"`); err == nil {
		t.Error("invalid response_timeout must be rejected")
	}
	if _, err := load(t, `request_timeout = "10"`); err == nil {
		t.Error("request_timeout without a unit must be rejected")
	}

	// Negative values rejected
	if _, err := load(t, `response_timeout = "-1m"`); err == nil {
		t.Error("negative response_timeout must be rejected")
	}
	if _, err := load(t, `request_timeout = "-5s"`); err == nil {
		t.Error("negative request_timeout must be rejected")
	}
}

// A per-target wake_timeout must bound the wake (not the global timeout), a
// failed wake must release IsWaking, and the next request must start a fresh
// wake generation.
func TestPerTargetWakeTimeoutHonoredAndRetryable(t *testing.T) {
	backend := newTestBackend(t, false)
	p, _, wol, hc, logger, ts := setupProxyWithPaths(t, backend, []string{"/models"}, 100*time.Millisecond)
	p.config.WakeTimeouts = map[string]time.Duration{"llamacpp": 400 * time.Millisecond}
	proxySrv := httptest.NewServer(http.HandlerFunc(p.handleRequest))
	t.Cleanup(proxySrv.Close)
	client := &http.Client{}

	// Target stays down for the whole test.
	hc.healthy.Store(false)
	ts.setHealth(false)

	// Request 1: /other is not a cached path, so it must go through the wake.
	// The wake must give up after the 400ms per-target timeout - not the
	// 10s global one - and the client gets a 503.
	start := time.Now()
	status, _, err := getFrom(t, client, proxySrv.URL+"/other", 3*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if elapsed >= 2*time.Second {
		t.Errorf("wake took %v; the per-target 400ms timeout was not honored (global is 10s)", elapsed)
	}
	if !strings.Contains(logger.text(), "after 400ms") {
		t.Errorf("expected the timeout error to report the 400ms per-target wake timeout:\n%s", logger.text())
	}
	// 1 initial packet + burst of 1 at t=0 + one re-burst after the first
	// failed check (each loop iteration re-sends the burst before waiting).
	if got := wol.sent.Load(); got != 3 {
		t.Errorf("WOL packets after first wake = %d, want 3", got)
	}
	ts.mu.RLock()
	waking := ts.IsWaking
	ts.mu.RUnlock()
	if waking {
		t.Fatal("IsWaking must be released after a failed wake")
	}

	// Request 2: a fresh wake generation must be able to start.
	start = time.Now()
	status, _, err = getFrom(t, client, proxySrv.URL+"/other", 3*time.Second)
	if err != nil || status != http.StatusServiceUnavailable {
		t.Fatalf("retry after failed wake: status=%d err=%v, want 503", status, err)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("second wake took %v; the per-target timeout was not honored", elapsed)
	}
	if got := wol.sent.Load(); got != 6 {
		t.Errorf("WOL packets after second wake = %d, want 6 (new generation sent its own 3)", got)
	}
}

// The request that triggers the wake and a request that joins it must both
// be served from the SAME wake generation: one WOL burst, both 200s.
func TestInitiatorAndJoinerShareOneWake(t *testing.T) {
	backend := newTestBackend(t, false)
	p, _, wol, hc, logger, _ := setupProxyWithPaths(t, backend, []string{"/models"}, 150*time.Millisecond)
	proxySrv := httptest.NewServer(http.HandlerFunc(p.handleRequest))
	t.Cleanup(proxySrv.Close)
	client := &http.Client{}

	// Target starts down; it boots 250ms after the wake begins. The wake
	// checks at ~150ms (miss) and ~650ms (hit, 500ms adaptive floor).
	hc.healthy.Store(false)
	ts := p.config.Targets["llamacpp"]
	ts.setHealth(false)

	go func() {
		time.Sleep(250 * time.Millisecond)
		hc.healthy.Store(true)
	}()

	type result struct {
		status int
		err    error
	}
	resA := make(chan result, 1)
	resB := make(chan result, 1)
	go func() {
		st, _, err := getFrom(t, client, proxySrv.URL+"/models", 5*time.Second)
		resA <- result{st, err}
	}()
	time.Sleep(100 * time.Millisecond) // wake is in progress by now
	go func() {
		st, _, err := getFrom(t, client, proxySrv.URL+"/models", 5*time.Second)
		resB <- result{st, err}
	}()

	a, b := <-resA, <-resB
	if a.err != nil || a.status != 200 {
		t.Fatalf("initiator: status=%d err=%v, want 200", a.status, a.err)
	}
	if b.err != nil || b.status != 200 {
		t.Fatalf("joiner: status=%d err=%v, want 200 (it must share the in-flight wake, not start a new one)", b.status, b.err)
	}
	if got := logger.count("waiting for server to wake"); got != 1 {
		t.Errorf("expected exactly 1 wake generation, got %d:\n%s", got, logger.text())
	}
	if logger.count("joining existing wait") == 0 {
		t.Errorf("expected a 'joining existing wait' log line:\n%s", logger.text())
	}
	// 1 initial + burst of 1 at t=0, one re-burst after the first failed
	// check at ~150ms, then the ~650ms check hits and no more bursts go out.
	if got := wol.sent.Load(); got != 3 {
		t.Errorf("WOL packets = %d, want 3 (single generation)", got)
	}
}

// With wake_health_check_interval set, the wake must poll at a fixed interval
// after the initial startup_time quiet period (here: 1.5s + 500ms), catching
// a machine that booted at 1.55s at ~2.0s - well before the adaptive
// 1.5s/750ms halving schedule would check again at ~2.25s.
func TestWakeFixedCheckInterval(t *testing.T) {
	backend := newTestBackend(t, false)
	p, _, wol, hc, _, ts := setupProxyWithPaths(t, backend, []string{"/models"}, 1500*time.Millisecond)
	p.config.WakeCheckIntervals = map[string]time.Duration{"llamacpp": 500 * time.Millisecond}
	proxySrv := httptest.NewServer(http.HandlerFunc(p.handleRequest))
	t.Cleanup(proxySrv.Close)
	client := &http.Client{}

	hc.healthy.Store(false)
	ts.setHealth(false)

	go func() {
		time.Sleep(1550 * time.Millisecond)
		hc.healthy.Store(true)
	}()

	start := time.Now()
	go func() {
		getFrom(t, client, proxySrv.URL+"/other", 5*time.Second)
	}()

	deadline := time.Now().Add(2250 * time.Millisecond)
	for {
		ts.mu.RLock()
		healthy := ts.IsHealthy
		ts.mu.RUnlock()
		if healthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wake did not confirm the target within 2.25s (fixed 500ms interval would hit it at ~2.0s; adaptive halving only at ~2.25s)")
		}
		time.Sleep(20 * time.Millisecond)
	}
	elapsed := time.Since(start)
	t.Logf("fixed-interval wake confirmed target after %v", elapsed.Round(time.Millisecond))

	if got := hc.checks.Load(); got != 2 {
		t.Errorf("health checks during wake = %d, want 2 (one at ~1.5s, one at ~2.0s)", got)
	}
	// 1 initial + burst of 1 at t=0, one re-burst after the failed check at
	// ~1.5s, then the ~2.0s check hits.
	if got := wol.sent.Load(); got != 3 {
		t.Errorf("WOL packets = %d, want 3 (single generation)", got)
	}
}

// End-to-end reproduction of the reported scenario:
//
//  1. machine is up, first /models request populates the cache;
//  2. machine sleeps and the cache ends up empty (the state this bug left
//     behind: previous wakes invalidated the cache, it was never repopulated
//     before the machine went to sleep again);
//  3. an impatient client (timeout much shorter than startup_time) requests
//     /models -> the wake starts; the client gives up after 200ms;
//  4. the machine boots; the wake must complete in the BACKGROUND even though
//     the clients are gone (previously: "context canceled", no confirmation,
//     no cache refresh, and every retry started a fresh WOL generation);
//  5. the post-wake cache refresh repopulates the cache;
//  6. machine sleeps again -> /models is served from the cache with no
//     further WOL packet.
func TestModelsCacheAfterClientTimeout(t *testing.T) {
	backend := newTestBackend(t, false)
	p, cs, wol, hc, logger, ts := setupProxyWithPaths(t, backend, []string{"/v1/models", "/models"}, 400*time.Millisecond)
	proxySrv := httptest.NewServer(http.HandlerFunc(p.handleRequest))
	t.Cleanup(proxySrv.Close)
	client := &http.Client{}

	// 1. machine up: first request populates the cache
	status, body, err := getFrom(t, client, proxySrv.URL+"/models", 5*time.Second)
	if err != nil || status != 200 {
		t.Fatalf("first request failed: status=%d err=%v", status, err)
	}
	if !strings.Contains(body, "model-a") {
		t.Fatalf("unexpected body: %s", body)
	}
	// The proxied body is cached when the proxy closes it, which can lag the
	// client-side ReadAll by a fraction of a second: poll briefly.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := cs.Get("llamacpp", "/models"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cache not populated while target is healthy (files: %v)\n%s", listCacheFiles(t, cs.rootPath), logger.text())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 2. machine goes to sleep
	hc.healthy.Store(false)
	ts.setHealth(false)

	// 3. cache ends up empty (as in the field after the bug)
	if err := os.RemoveAll(filepath.Join(cs.rootPath, "llamacpp")); err != nil {
		t.Fatal(err)
	}

	// 4. impatient client requests /models: 200ms timeout << 400ms startup
	go func() {
		getFrom(t, client, proxySrv.URL+"/models", 200*time.Millisecond)
	}()

	// a second client arrives while the wake is in progress: it must join the
	// existing wake, not send another WOL burst
	time.Sleep(100 * time.Millisecond)
	go func() {
		getFrom(t, client, proxySrv.URL+"/models", 300*time.Millisecond)
	}()

	// 5. the machine boots 250ms after the wake started
	time.Sleep(250 * time.Millisecond)
	hc.healthy.Store(true)

	// 6. the wake must complete in the background although both clients
	//    already timed out
	deadline = time.Now().Add(3 * time.Second)
	for {
		ts.mu.RLock()
		healthy := ts.IsHealthy
		ts.mu.RUnlock()
		if healthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wake did not complete after the clients left:\n%s", logger.text())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 7. the post-wake cache refresh must have repopulated the cache
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, ok := cs.Get("llamacpp", "/models"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cache not repopulated after wake:\n%s", logger.text())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// One wake generation: 1 initial packet + the 1-packet burst. Joiners and
	// later requests must not start new generations.
	if got := logger.count("waiting for server to wake"); got != 1 {
		t.Errorf("expected exactly 1 wake generation, got %d:\n%s", got, logger.text())
	}
	if got := wol.sent.Load(); got != 2 {
		t.Errorf("expected 2 WOL packets (1 initial + burst of 1), got %d", got)
	}

	// 8. machine sleeps again: /models must come from the cache, instantly,
	//    without any further WOL
	hc.healthy.Store(false)
	ts.setHealth(false)
	start := time.Now()
	status, body, err = getFrom(t, client, proxySrv.URL+"/models", 5*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("offline /models request failed: %v", err)
	}
	if status != 200 {
		t.Fatalf("offline /models status=%d (expected 200 from cache)", status)
	}
	if !strings.Contains(body, "model-a") {
		t.Fatalf("unexpected cached body: %s", body)
	}
	if elapsed > 2*time.Second {
		t.Errorf("offline /models took %v; expected an instant cache serve", elapsed)
	}
	if got := wol.sent.Load(); got != 2 {
		t.Errorf("WOL sent again for a cached /models request (total=%d)", got)
	}

	for _, l := range strings.Split(logger.text(), "\n") {
		t.Logf("| %s", l)
	}
	if logger.count("Serving cached response for GET /models") == 0 {
		t.Error("expected a 'Serving cached response for GET /models' log line")
	}
}
