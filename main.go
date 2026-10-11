package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// Interfaces for dependency injection
type HealthChecker interface {
	Check(ctx context.Context, endpoint string, source string) bool
	StartBackgroundChecks(ctx context.Context, machines map[string]*Machine, routes []*Route, interval time.Duration)
	WaitForInitialChecks(ctx context.Context) error
	CloseIdleConnections()
}

type WOLSender interface {
	SendWOL(macAddr, broadcastIP string, port int) error
}

type SSHExecutor interface {
	ExecuteCommand(host, user, keyPath, command string) error
}

type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

const tcpScheme = "tcp://"

// version is replaced by the release build. Keep a useful value for local
// builds and tests that do not supply linker flags.
var version = "dev"

// shutdownGrace is how long in-flight requests get to finish on shutdown.
const shutdownGrace = 15 * time.Second

// healthCheckTimeout caps a single health check, HTTP or TCP alike. The TCP cap has
// to live on the dialer rather than relying on the caller's context: waitForWake and
// markReadyIfHealthy pass their caller's context through undeadlined, and a dropped
// SYN would otherwise block for the kernel's whole retry schedule.
const healthCheckTimeout = 5 * time.Second

// A retried accept backs off between attempts, so a listener that is failing for a
// reason we cannot fix does not spin a core while it recovers.
const (
	acceptRetryDelayMin = 5 * time.Millisecond
	acceptRetryDelayMax = 1 * time.Second
)

// isTemporaryAcceptError reports whether an Accept failure is worth retrying. These
// are conditions a listener recovers from unaided: a client that reset during the
// handshake, or the process briefly out of descriptors or buffers. Anything else
// means the listener is broken, and that has to reach the operator rather than
// becoming a silent retry loop.
func isTemporaryAcceptError(err error) bool {
	return errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type Clock interface {
	Now() time.Time
	NewTicker(d time.Duration) Ticker
	After(d time.Duration) <-chan time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time                         { return time.Now() }
func (RealClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (RealClock) NewTicker(d time.Duration) Ticker       { return &realTicker{time.NewTicker(d)} }

type realTicker struct{ t *time.Ticker }

func (r *realTicker) C() <-chan time.Time { return r.t.C }
func (r *realTicker) Stop()               { r.t.Stop() }

// Config structs
type Config struct {
	Port                  string         `toml:"port"`
	Timeout               string         `toml:"timeout"`
	StartupTime           string         `toml:"startup_time,omitempty"`
	RequestHeaderTimeout  string         `toml:"request_header_timeout,omitempty"`
	ResponseHeaderTimeout string         `toml:"response_header_timeout,omitempty"`
	ServerReadTimeout     string         `toml:"server_read_timeout,omitempty"`
	ServerWriteTimeout    string         `toml:"server_write_timeout,omitempty"`
	ServerIdleTimeout     string         `toml:"server_idle_timeout,omitempty"`
	ClientHostnameLookup  *bool          `toml:"client_hostname_lookup,omitempty"`
	PollInterval          string         `toml:"poll_interval"`
	HealthCheckInterval   string         `toml:"health_check_interval"`
	HealthCacheDuration   string         `toml:"health_cache_duration"`
	SSLCertificate        string         `toml:"ssl_certificate,omitempty"`
	SSLCertificateKey     string         `toml:"ssl_certificate_key,omitempty"`
	CacheConfig           CacheConfig    `toml:"cache,omitempty"`
	Targets               []Target       `toml:"targets,omitempty"` // legacy, superseded by machines + routes
	Machines              []MachineEntry `toml:"machines,omitempty"`
	Routes                []RouteEntry   `toml:"routes,omitempty"`
}

// MachineEntry is a [[machines]] block as written in the config file.
type MachineEntry struct {
	Name                    string `toml:"name"`
	MacAddress              string `toml:"mac_address,omitempty"`
	BroadcastIP             string `toml:"broadcast_ip,omitempty"`
	WolPort                 int    `toml:"wol_port,omitempty"`
	WolBurstCount           int    `toml:"wol_burst_count,omitempty"`
	WakeTimeout             string `toml:"wake_timeout,omitempty"`
	WakeHealthCheckInterval string `toml:"wake_health_check_interval,omitempty"`
	HealthCheck             string `toml:"health_check,omitempty"`
	SSHHost                 string `toml:"ssh_host,omitempty"`
	SSHUser                 string `toml:"ssh_user,omitempty"`
	SSHKeyPath              string `toml:"ssh_key_path,omitempty"`
	ShutdownCommand         string `toml:"shutdown_command,omitempty"`
	ShutdownHTTPUrl         string `toml:"shutdown_http_url,omitempty"`
	ShutdownHTTPMethod      string `toml:"shutdown_http_method,omitempty"`
	ShutdownHTTPOKStatus    int    `toml:"shutdown_http_ok_status,omitempty"`
	InactivityThreshold     string `toml:"inactivity_threshold,omitempty"`
}

// RouteEntry is a [[routes]] block as written in the config file.
type RouteEntry struct {
	Machine     string `toml:"machine"`
	Hostname    string `toml:"hostname,omitempty"`
	ListenPort  int    `toml:"listen_port,omitempty"`
	Destination string `toml:"destination,omitempty"`
	HealthCheck string `toml:"health_check,omitempty"`
}

// CacheConfig is the optional [cache] block. When a machine is offline, GET
// responses for the configured paths are served from disk instead of waking
// it: the client gets a full answer while the box stays asleep, and the
// cache is refreshed again once the machine is reachable.
type CacheConfig struct {
	Enabled              bool               `toml:"enabled"`
	RootPath             string             `toml:"root_path,omitempty"`
	TTL                  string             `toml:"ttl,omitempty"`
	MaxResponseSizeBytes int64              `toml:"max_response_size_bytes,omitempty"`
	WarmInterval         string             `toml:"warm_interval,omitempty"`
	Routes               []CacheRouteConfig `toml:"routes,omitempty"`
}

// CacheRouteConfig is a [[cache.routes]] block: the paths cached for one route.
type CacheRouteConfig struct {
	Route string   `toml:"route"`
	Paths []string `toml:"paths"`
}

type Target struct {
	Name                 string `toml:"name"`
	Hostname             string `toml:"hostname"`
	Destination          string `toml:"destination"`
	HealthEndpoint       string `toml:"health_endpoint"`
	MacAddress           string `toml:"mac_address"`
	BroadcastIP          string `toml:"broadcast_ip"`
	WolPort              int    `toml:"wol_port"`
	SSHHost              string `toml:"ssh_host"`
	SSHUser              string `toml:"ssh_user"`
	SSHKeyPath           string `toml:"ssh_key_path"`
	ShutdownCommand      string `toml:"shutdown_command"`
	ShutdownHTTPUrl      string `toml:"shutdown_http_url"`
	ShutdownHTTPMethod   string `toml:"shutdown_http_method"`
	ShutdownHTTPOKStatus int    `toml:"shutdown_http_ok_status"`
	InactivityThreshold  string `toml:"inactivity_threshold"`
}

// Machine is a host that is woken, health-checked and shut down as one unit,
// however many routes point at it.
type MachineConfig struct {
	MacAddress              string
	BroadcastIP             string
	WolPort                 int
	WolBurstCount           int           // WOL packets per burst (1-10, 0 = default)
	WakeTimeout             time.Duration // per-machine wake bound (0 = global timeout)
	WakeHealthCheckInterval time.Duration // fixed wake poll (0 = adaptive halving)
	HealthCheck             string
	SSHHost                 string
	SSHUser                 string
	SSHKeyPath              string
	ShutdownCommand         string
	ShutdownHTTPUrl         string
	ShutdownHTTPMethod      string
	ShutdownHTTPOKStatus    int
	InactivityThreshold     time.Duration
}

// Route is one way in to a machine.
type Route struct {
	Name        string
	Machine     *Machine
	Hostname    string
	ListenPort  int
	Destination string
	// HealthCheck is this route's readiness check: can this route serve? It is
	// distinct from the machine's liveness check, which answers whether the box is
	// up at all. Defaults to dialing Destination.
	HealthCheck string

	IsReady   bool
	LastCheck time.Time
	mu        sync.RWMutex
}

// IsTCP reports whether this route is reached by its own listening socket rather
// than by Host header. A route has a hostname or a listen port, never both.
func (r *Route) IsTCP() bool { return r.ListenPort != 0 }

// routing is the runtime routing model: machines and the routes that reach them.
type routing struct {
	machines     map[string]*Machine
	routes       []*Route
	byHostname   map[string]*Route
	byListenPort map[int]*Route
}

type ProxyConfig struct {
	Port                  string
	Timeout               time.Duration
	StartupTime           time.Duration
	RequestHeaderTimeout  time.Duration
	ResponseHeaderTimeout time.Duration
	ServerReadTimeout     time.Duration
	ServerWriteTimeout    time.Duration
	ServerIdleTimeout     time.Duration
	ClientHostnameLookup  bool
	PollInterval          time.Duration
	HealthCheckInterval   time.Duration
	HealthCacheDuration   time.Duration
	Machines              map[string]*Machine
	Routes                []*Route
	RoutesByHostname      map[string]*Route
	RoutesByListenPort    map[int]*Route
	SSLCertificate        string
	SSLCertificateKey     string
	CacheEnabled          bool
	CacheRootPath         string
	CacheTTL              time.Duration
	CacheMaxResponseSize  int64
	CacheWarmInterval     time.Duration
	CacheRoutes           map[string][]string // route name -> cached path patterns
}

type Machine struct {
	Name         string
	Config       *MachineConfig
	IsHealthy    bool
	LastCheck    time.Time
	IsWaking     bool
	wakeGen      int       // monotonically increasing generation counter for wake operations
	wake         *wakeInfo // in-flight (or most recently completed) wake generation
	LastActivity time.Time
	openConns    int
	mu           sync.RWMutex
}

// wakeInfo carries the completion state of one wake generation. The error is
// published and the done channel is closed in the same critical section
// (finishWake), so a waiter that observes done always reads the result of the
// exact generation it joined - even if a new wake has already started by
// then.
type wakeInfo struct {
	gen  int
	done chan struct{}
	err  error
}

// openConnections reports how many forwarded connections are currently open. A
// long-lived idle connection — an ssh session is the motivating case — moves no
// bytes, so LastActivity alone cannot tell the machine is still in use.
func (m *Machine) openConnections() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.openConns
}

func (m *Machine) holdConnection() {
	m.mu.Lock()
	m.openConns++
	m.mu.Unlock()
}

// releaseConnection decrements the in-flight counter and stamps LastActivity to
// now. Stamping on release is what makes the inactivity countdown start at
// disconnect: a long-running session — an ssh login left open for hours — would
// otherwise carry a stale LastActivity from when it began, and the very next
// inactivity tick after logout would exceed the threshold and shut the box down.
func (m *Machine) releaseConnection(now time.Time) {
	m.mu.Lock()
	if m.openConns > 0 {
		m.openConns--
	}
	m.LastActivity = now
	m.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Static response cache
// ---------------------------------------------------------------------------

type cacheEntry struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"-"`
	Timestamp  time.Time           `json:"timestamp"`
	Path       string              `json:"path"`
}

// CacheStore persists GET responses for configured route paths on disk so
// they can be served while the machine behind the route is asleep.
type CacheStore struct {
	rootPath    string
	ttl         time.Duration
	maxSize     int64
	logger      Logger
	entriesMu   sync.RWMutex
	entries     map[string]*cacheEntry
	routePaths  map[string][]string // route name -> list of patterns
	keyToRoute  map[string]string   // cache key -> route name
	keyToPath   map[string]string   // cache key -> path
	accessOrder []string
	maxEntries  int
	lastHashes  map[string][]byte // cache key -> last SHA-256 hash of body
}

func NewCacheStore(rootPath string, ttl time.Duration, maxSize int64, routePaths map[string][]string, logger Logger) *CacheStore {
	cs := &CacheStore{
		rootPath:    rootPath,
		ttl:         ttl,
		maxSize:     maxSize,
		logger:      logger,
		entries:     make(map[string]*cacheEntry),
		routePaths:  routePaths,
		keyToRoute:  make(map[string]string),
		keyToPath:   make(map[string]string),
		accessOrder: []string{},
		maxEntries:  1000,
		lastHashes:  make(map[string][]byte),
	}

	if err := os.MkdirAll(rootPath, 0755); err != nil {
		logger.Error("Failed to create cache directory %s: %v", rootPath, err)
	}

	cs.loadAll()

	return cs
}

func (cs *CacheStore) key(routeName, urlPath string) string {
	hash := sha256.Sum256([]byte(routeName + urlPath))
	return fmt.Sprintf("%x", hash[:16])
}

func (cs *CacheStore) cacheFilePath(routeName, urlPath string) string {
	return filepath.Join(cs.rootPath, routeName, cs.key(routeName, urlPath)+".cache")
}

func (cs *CacheStore) load(routeName, urlPath string) (*cacheEntry, bool) {
	// urlPath is a URL path: always slash-separated, so clean it with
	// path.Clean rather than filepath.Clean, which would rewrite separators
	// on Windows and desynchronize keys from the request paths that produced
	// them.
	urlPath = path.Clean(urlPath)
	if urlPath == "." || urlPath == "" {
		return nil, false
	}

	cacheFile := cs.cacheFilePath(routeName, urlPath)

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, false
	}

	var entry cacheEntry
	if meta, body, ok := parseCacheEnvelope(data); ok && meta.Path == urlPath {
		entry = meta
		entry.Body = body
	} else {
		// Legacy two-file layout: body in cacheFile, metadata in cacheFile+".meta"
		metaData, err := os.ReadFile(cacheFile + ".meta")
		if err != nil {
			return nil, false
		}
		if err := json.Unmarshal(metaData, &entry); err != nil {
			return nil, false
		}
		entry.Body = data
	}

	if time.Since(entry.Timestamp) > cs.ttl {
		os.Remove(cacheFile)
		os.Remove(cacheFile + ".meta")
		return nil, false
	}

	cs.entriesMu.Lock()
	k := cs.key(routeName, urlPath)
	if _, exists := cs.entries[k]; !exists {
		cs.entries[k] = &entry
		cs.keyToRoute[k] = routeName
		cs.keyToPath[k] = urlPath
		cs.addToAccessOrder(k)
	}
	cs.entriesMu.Unlock()

	return &entry, true
}

func (cs *CacheStore) Save(routeName, urlPath string, statusCode int, headers http.Header, body []byte) {
	urlPath = path.Clean(urlPath)
	if urlPath == "." || urlPath == "" {
		return
	}

	if int64(len(body)) > cs.maxSize {
		cs.logger.Error("Response too large for cache (%d bytes) for %s %s", len(body), routeName, urlPath)
		return
	}

	bodyHash := sha256.Sum256(body)
	cacheFile := cs.cacheFilePath(routeName, urlPath)

	cs.entriesMu.Lock()
	k := cs.key(routeName, urlPath)
	if lastHash, exists := cs.lastHashes[k]; exists && bytes.Equal(lastHash, bodyHash[:]) {
		// Unchanged content only allows skipping the write while the cache
		// file is still on disk: the file can disappear independently of
		// lastHashes (TTL expiry in load, manual cleanup, ...). Skipping the
		// write in that case would leave the cache empty forever for
		// unchanged responses (e.g. a static model list), sending WOL on
		// every offline request.
		if _, err := os.Stat(cacheFile); err == nil {
			cs.entriesMu.Unlock()
			cs.logger.Debug("Cache unchanged for %s %s, skipping write", routeName, urlPath)
			return
		}
	}
	cs.entriesMu.Unlock()

	cacheDir := filepath.Join(cs.rootPath, routeName)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		cs.logger.Error("Failed to create cache directory %s: %v", cacheDir, err)
		return
	}

	meta := &cacheEntry{
		StatusCode: statusCode,
		Headers:    sanitizeCachedHeaders(headers),
		Body:       body,
		Timestamp:  time.Now(),
		Path:       urlPath,
	}

	// The on-disk entry is a single file:
	//
	//	[4]byte metadata length (little-endian) | metadata JSON | body
	//
	// Publishing it takes one atomic rename, so a concurrent reader can
	// never observe a body without its metadata. With the older two-file
	// layout there was a window between the body rename and the metadata
	// rename in which a request saw a cache miss and sent WOL for a
	// response that was actually being cached.
	metaData, err := json.Marshal(meta)
	if err != nil {
		cs.logger.Error("Failed to marshal cache metadata: %v", err)
		return
	}

	envelope := make([]byte, 4, 4+len(metaData)+len(body))
	binary.LittleEndian.PutUint32(envelope, uint32(len(metaData)))
	envelope = append(envelope, metaData...)
	envelope = append(envelope, body...)

	if err := writeFileAtomic(cacheFile, envelope); err != nil {
		cs.logger.Error("Failed to write cache file %s: %v", cacheFile, err)
		return
	}
	// Drop a legacy metadata sidecar left behind by older versions.
	os.Remove(cacheFile + ".meta")

	cs.entriesMu.Lock()
	cs.entries[k] = meta
	cs.keyToRoute[k] = routeName
	cs.keyToPath[k] = urlPath
	cs.addToAccessOrder(k)
	cs.lastHashes[k] = bodyHash[:]
	cs.entriesMu.Unlock()

	cs.logger.Info("Cache updated for %s %s", routeName, urlPath)
}

// hopByHopHeaders are connection-specific or framing headers that must not be
// stored and replayed when a cached response is served from disk: the server
// sending the cached response re-adds the correct framing (Content-Length or
// chunking) for the actual body.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"Content-Length",
}

func sanitizeCachedHeaders(headers http.Header) http.Header {
	sanitized := make(http.Header, len(headers))
	for key, values := range headers {
		skip := false
		for _, hop := range hopByHopHeaders {
			if strings.EqualFold(key, hop) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		sanitized[key] = values
	}
	return sanitized
}

// parseCacheEnvelope splits a single-file cache entry
// ([4]byte metadata length (little-endian) | metadata JSON | body).
// ok is false when data is not an envelope (e.g. a legacy two-file body), in
// which case the caller falls back to the legacy layout.
func parseCacheEnvelope(data []byte) (meta cacheEntry, body []byte, ok bool) {
	if len(data) < 4 {
		return
	}
	metaLen := int(binary.LittleEndian.Uint32(data[:4]))
	if metaLen <= 0 || 4+metaLen > len(data) {
		return
	}
	if err := json.Unmarshal(data[4:4+metaLen], &meta); err != nil {
		return
	}
	if meta.Path == "" {
		return
	}
	meta.Body = data[4+metaLen:]
	body = meta.Body
	ok = true
	return
}

// writeFileAtomic writes data to a temp file in the same directory and renames
// it into place, so readers never see a partially written file.
func writeFileAtomic(filePath string, data []byte) error {
	tmpFile := filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpFile, filePath); err != nil {
		os.Remove(tmpFile)
		return err
	}
	return nil
}

func (cs *CacheStore) Get(routeName, urlPath string) (*http.Response, bool) {
	entry, ok := cs.load(routeName, urlPath)
	if !ok {
		return nil, false
	}

	resp := &http.Response{
		StatusCode: entry.StatusCode,
		Status:     http.StatusText(entry.StatusCode),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     entry.Headers,
		Body:       io.NopCloser(bytes.NewReader(entry.Body)),
	}

	return resp, true
}

func (cs *CacheStore) GetCachedPathsForRoute(routeName string) []string {
	cs.entriesMu.RLock()
	defer cs.entriesMu.RUnlock()

	routePaths, exists := cs.routePaths[routeName]
	if !exists || len(routePaths) == 0 {
		return nil
	}

	var result []string
	for _, pattern := range routePaths {
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			for key := range cs.keyToPath {
				if cs.keyToRoute[key] == routeName {
					if p := cs.keyToPath[key]; p != "" && strings.HasPrefix(p, prefix) {
						result = append(result, p)
					}
				}
			}
		} else {
			result = append(result, pattern)
		}
	}

	return result
}

func (cs *CacheStore) addToAccessOrder(key string) {
	for i, k := range cs.accessOrder {
		if k == key {
			cs.accessOrder = append(cs.accessOrder[:i], cs.accessOrder[i+1:]...)
			break
		}
	}
	cs.accessOrder = append(cs.accessOrder, key)
	for len(cs.accessOrder) > cs.maxEntries {
		oldest := cs.accessOrder[0]
		cs.accessOrder = cs.accessOrder[1:]
		delete(cs.entries, oldest)
		delete(cs.keyToRoute, oldest)
		delete(cs.keyToPath, oldest)
	}
}

func (cs *CacheStore) loadAll() {
	routes := make(map[string]bool)
	for routeName := range cs.routePaths {
		routes[routeName] = true
	}

	for routeName := range routes {
		dir := filepath.Join(cs.rootPath, routeName)
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".cache") {
				continue
			}

			if strings.HasSuffix(file.Name(), ".meta.cache") {
				continue
			}

			cacheFile := filepath.Join(dir, file.Name())

			var entry cacheEntry
			if metaData, err := os.ReadFile(cacheFile + ".meta"); err == nil {
				// Legacy two-file layout: body in cacheFile, metadata in the
				// ".meta" sidecar
				if err := json.Unmarshal(metaData, &entry); err != nil {
					continue
				}
				body, err := os.ReadFile(cacheFile)
				if err != nil {
					continue
				}
				entry.Body = body
			} else {
				// Single-file envelope layout
				data, err := os.ReadFile(cacheFile)
				if err != nil {
					continue
				}
				if meta, body, ok := parseCacheEnvelope(data); !ok {
					continue
				} else {
					entry = meta
					entry.Body = body
				}
			}

			if time.Since(entry.Timestamp) > cs.ttl {
				os.Remove(cacheFile)
				os.Remove(cacheFile + ".meta")
				continue
			}

			k := file.Name()[:len(file.Name())-len(".cache")]
			cs.entries[k] = &entry
			cs.keyToRoute[k] = routeName
			cs.keyToPath[k] = entry.Path
			cs.addToAccessOrder(k)
		}
	}

	cs.logger.Info("Loaded %d cache entries", len(cs.entries))
}

func (cs *CacheStore) Cleanup() {
	cs.entriesMu.Lock()
	defer cs.entriesMu.Unlock()

	keysToRemove := []string{}

	for k, entry := range cs.entries {
		if time.Since(entry.Timestamp) > cs.ttl {
			keysToRemove = append(keysToRemove, k)
		}
	}

	for _, k := range keysToRemove {
		routeName := cs.keyToRoute[k]
		urlPath := cs.keyToPath[k]

		delete(cs.entries, k)
		delete(cs.keyToRoute, k)
		delete(cs.keyToPath, k)
		delete(cs.lastHashes, k)

		// Also remove the expired files from disk, not just the in-memory bookkeeping.
		if routeName != "" && urlPath != "" {
			cacheFile := cs.cacheFilePath(routeName, urlPath)
			os.Remove(cacheFile)
			os.Remove(cacheFile + ".meta")
		}
	}

	if len(keysToRemove) > 0 {
		cs.logger.Info("Cleaned up %d expired cache entries", len(keysToRemove))
	}
}

func (cs *CacheStore) Close() {
	cs.Cleanup()
}

// catchingBody tees the proxied response body into a buffer and hands the
// complete copy to onDone when the body is closed, so the cache is written
// without buffering the whole response in front of the client.
type catchingBody struct {
	io.Reader
	original io.ReadCloser
	onDone   func()
	closed   bool
}

func (cb *catchingBody) Close() error {
	if cb.closed {
		return nil
	}
	cb.closed = true

	if cb.onDone != nil {
		cb.onDone()
	}
	if cb.original != nil {
		return cb.original.Close()
	}
	return nil
}

// Health checker: dispatches on the endpoint scheme — tcp:// dials, anything else is an HTTP GET
type EndpointHealthChecker struct {
	client           *http.Client
	logger           Logger
	dialer           net.Dialer
	clock            Clock
	initialCheckDone map[string]bool
	initialCheckMu   sync.RWMutex
	initialWaitGroup sync.WaitGroup
}

func NewEndpointHealthChecker(logger Logger, clock Clock) *EndpointHealthChecker {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	return &EndpointHealthChecker{
		client: &http.Client{
			Timeout:   healthCheckTimeout,
			Transport: transport,
		},
		dialer:           net.Dialer{Timeout: healthCheckTimeout},
		logger:           logger,
		clock:            clock,
		initialCheckDone: make(map[string]bool),
	}
}

func (h *EndpointHealthChecker) CloseIdleConnections() {
	if transport, ok := h.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (h *EndpointHealthChecker) Check(ctx context.Context, endpoint string, source string) bool {
	if address, ok := strings.CutPrefix(endpoint, tcpScheme); ok {
		return h.checkTCP(ctx, address, source)
	}
	return h.checkHTTP(ctx, endpoint, source)
}

// checkTCP reports liveness by opening and immediately closing a connection. For
// anything that is not an HTTP server — sshd being the motivating case — accepting
// a connection is the only readiness signal there is.
func (h *EndpointHealthChecker) checkTCP(ctx context.Context, address string, source string) bool {
	conn, err := h.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		h.logger.Info("Health check (%s) failed for %s%s: %v", source, tcpScheme, address, err)
		return false
	}
	conn.Close()
	return true
}

func (h *EndpointHealthChecker) checkHTTP(ctx context.Context, endpoint string, source string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		h.logger.Info("Health check (%s) failed for %s: %v", source, endpoint, err)
		return false
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Info("Health check (%s) failed for %s: %v", source, endpoint, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.logger.Info("Health check (%s) failed for %s: status %d", source, endpoint, resp.StatusCode)
		return false
	}

	return true
}

func (h *EndpointHealthChecker) StartBackgroundChecks(ctx context.Context, machines map[string]*Machine, routes []*Route, interval time.Duration) {
	for name, machine := range machines {
		h.initialWaitGroup.Add(1)
		go h.backgroundCheck(ctx, name, machine, routesTo(machine, routes), interval)
	}
}

func (h *EndpointHealthChecker) WaitForInitialChecks(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		h.initialWaitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *EndpointHealthChecker) backgroundCheck(ctx context.Context, name string, machine *Machine, routes []*Route, interval time.Duration) {
	// Perform initial check
	h.performCheck(ctx, name, machine, routes)
	h.markInitialCheckDone(name)
	h.initialWaitGroup.Done()

	ticker := h.clock.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			h.performCheck(ctx, name, machine, routes)
		}
	}
}

func (h *EndpointHealthChecker) performCheck(ctx context.Context, name string, machine *Machine, routes []*Route) {
	machine.mu.RLock()
	isWaking := machine.IsWaking
	machine.mu.RUnlock()
	if isWaking {
		h.logger.Info("Background health check for %s (%s) running while wake is in progress",
			name, machine.Config.HealthCheck)
	}

	checkStarted := h.clock.Now()
	checkCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()

	healthy := h.Check(checkCtx, machine.Config.HealthCheck, "background")

	machine.mu.Lock()
	previousHealth := machine.IsHealthy
	machine.IsHealthy = healthy
	machine.LastCheck = h.clock.Now()
	machine.mu.Unlock()

	if healthy != previousHealth {
		status := "DOWN"
		if healthy {
			status = "UP"
		}
		h.logger.Info("Health check for %s (%s): %s", name, machine.Config.HealthCheck, status)
	}

	if !healthy && previousHealth {
		h.logger.Info(
			"Background health check for %s (%s): downgrading healthy to unhealthy (check took %v)",
			name, machine.Config.HealthCheck, h.clock.Now().Sub(checkStarted).Round(time.Millisecond),
		)
	}

	if !healthy {
		h.CloseIdleConnections()
	}

	h.checkRoutes(ctx, machine, routes, healthy)
}

// checkRoutes polls each route's readiness, but only while its machine is live. A
// machine that is meant to be asleep most of the time would otherwise generate a
// failed connection per route per interval, forever.
func (h *EndpointHealthChecker) checkRoutes(ctx context.Context, machine *Machine, routes []*Route, machineLive bool) {
	for _, route := range routes {
		if !machineLive {
			route.mu.Lock()
			route.IsReady = false
			route.mu.Unlock()
			continue
		}

		checkCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
		ready := h.Check(checkCtx, route.HealthCheck, "background")
		cancel()

		route.mu.Lock()
		previous := route.IsReady
		route.IsReady = ready
		route.LastCheck = h.clock.Now()
		route.mu.Unlock()

		if ready != previous {
			status := "NOT READY"
			if ready {
				status = "READY"
			}
			h.logger.Info("Route %s on machine %s: %s", route.Name, machine.Name, status)
		}
	}
}

// routesTo returns the routes that reach the given machine.
func routesTo(machine *Machine, routes []*Route) []*Route {
	matched := make([]*Route, 0, len(routes))
	for _, route := range routes {
		if route.Machine == machine {
			matched = append(matched, route)
		}
	}
	return matched
}

func (h *EndpointHealthChecker) markInitialCheckDone(name string) {
	h.initialCheckMu.Lock()
	defer h.initialCheckMu.Unlock()
	h.initialCheckDone[name] = true
}

// Wake-on-LAN sender implementation
type UDPWOLSender struct {
	logger Logger
}

func NewUDPWOLSender(logger Logger) *UDPWOLSender {
	return &UDPWOLSender{logger: logger}
}

// SSH command executor implementation
type DefaultSSHExecutor struct {
	logger Logger
}

func NewDefaultSSHExecutor(logger Logger) *DefaultSSHExecutor {
	return &DefaultSSHExecutor{logger: logger}
}

func (s *DefaultSSHExecutor) ExecuteCommand(host, user, keyPath, command string) error {
	// Read private key
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("unable to read private key: %w", err)
	}

	// Create signer
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %w", err)
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Connect to SSH server
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return fmt.Errorf("unable to connect to SSH server: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("unable to create SSH session: %w", err)
	}
	defer session.Close()

	// Execute command
	s.logger.Info("Executing SSH command on %s@%s: %s", user, host, command)
	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Errorf("command execution failed: %w, output: %s", err, string(output))
	}

	s.logger.Info("SSH command executed successfully on %s@%s, output: %s", user, host, string(output))
	return nil
}

func (w *UDPWOLSender) SendWOL(macAddr, broadcastIP string, port int) error {
	// Parse MAC address
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	// Create magic packet
	packet := w.createMagicPacket(mac)

	// Send UDP packet
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", broadcastIP, port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send WOL packet: %w", err)
	}

	w.logger.Info("WOL packet sent to %s via %s:%d", macAddr, broadcastIP, port)
	return nil
}

func (w *UDPWOLSender) createMagicPacket(mac net.HardwareAddr) []byte {
	var packet bytes.Buffer

	// 6 bytes of 0xFF
	for i := 0; i < 6; i++ {
		packet.WriteByte(0xFF)
	}

	// 16 repetitions of the MAC address
	for i := 0; i < 16; i++ {
		packet.Write(mac)
	}

	return packet.Bytes()
}

// Main proxy service
type ProxyService struct {
	config         *ProxyConfig
	healthChecker  HealthChecker
	wolSender      WOLSender
	sshExecutor    SSHExecutor
	clientResolver *clientResolver
	logger         Logger
	clock          Clock
	cache          *CacheStore
}

func NewProxyService(
	config *ProxyConfig,
	healthChecker HealthChecker,
	wolSender WOLSender,
	sshExecutor SSHExecutor,
	logger Logger,
	clock Clock,
	cache *CacheStore,
) *ProxyService {
	return &ProxyService{
		config:         config,
		healthChecker:  healthChecker,
		wolSender:      wolSender,
		sshExecutor:    sshExecutor,
		clientResolver: newClientResolver(config.ClientHostnameLookup),
		logger:         logger,
		clock:          clock,
		cache:          cache,
	}
}

func (p *ProxyService) shutdownMachine(machineName string) error {
	machineState, exists := p.config.Machines[machineName]
	if !exists {
		return fmt.Errorf("unknown machine: %s", machineName)
	}

	cfg := machineState.Config
	if (cfg.SSHHost == "" || cfg.SSHUser == "" || cfg.SSHKeyPath == "" || cfg.ShutdownCommand == "") && cfg.ShutdownHTTPUrl == "" {
		return fmt.Errorf("machine %s is missing SSH configuration or shutdown command or shutdown HTTP URL", machineName)
	}

	p.logger.Info("Shutting down machine %s due to inactivity", machineName)
	if cfg.ShutdownHTTPUrl != "" {
		// Attempt to shut down via HTTP request
		method := cfg.ShutdownHTTPMethod
		if method == "" {
			method = "POST" // Default to POST if not specified
		}

		req, err := http.NewRequest(method, cfg.ShutdownHTTPUrl, nil)
		if err != nil {
			return fmt.Errorf("failed to create shutdown request: %w", err)
		}

		// Send the request
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send shutdown request: %w", err)
		}
		defer resp.Body.Close()

		// Accept any 2xx status by default; allow explicit status override
		if cfg.ShutdownHTTPOKStatus != 0 {
			if resp.StatusCode != cfg.ShutdownHTTPOKStatus {
				return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
			}
		} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
		}

	} else {
		err := p.sshExecutor.ExecuteCommand(cfg.SSHHost, cfg.SSHUser, cfg.SSHKeyPath, cfg.ShutdownCommand)
		if err != nil {
			p.logger.Error("Failed to shut down machine %s: %v", machineName, err)
			return err
		}
	}

	// Mark the machine as unhealthy after shutdown
	machineState.mu.Lock()
	machineState.IsHealthy = false
	machineState.mu.Unlock()
	p.healthChecker.CloseIdleConnections()

	p.logger.Info("Machine %s has been shut down", machineName)
	return nil
}

func (p *ProxyService) startInactivityMonitor(ctx context.Context) {
	// Check every 10 seconds for inactive machines
	ticker := p.clock.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			p.checkInactiveMachines()
		}
	}
}

func (p *ProxyService) checkInactiveMachines() {
	now := p.clock.Now()

	for name, machineState := range p.config.Machines {
		// Skip machines without inactivity threshold
		threshold := machineState.Config.InactivityThreshold
		if threshold == 0 {
			continue
		}

		// Skip machines that are not healthy (already down)
		machineState.mu.RLock()
		isHealthy := machineState.IsHealthy
		lastActivity := machineState.LastActivity
		openConns := machineState.openConns
		machineState.mu.RUnlock()

		if !isHealthy {
			continue
		}

		if openConns > 0 {
			continue
		}

		// Check if the machine has been inactive for too long
		inactiveDuration := now.Sub(lastActivity)
		if inactiveDuration > threshold {
			p.logger.Info("Machine %s has been inactive for %v (threshold: %v), shutting down",
				name, inactiveDuration.Round(time.Second), threshold)

			if err := p.shutdownMachine(name); err != nil {
				p.logger.Error("Failed to shut down inactive machine %s: %v", name, err)
			}
		}
	}
}

// warmMachine refreshes the cached paths of every HTTP route pointing at
// machine, fetching each from the route's destination while it is reachable.
func (p *ProxyService) warmMachine(machine *Machine) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	p.logger.Debug("Starting cache warmup for machine: %s", machine.Name)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    true,
		},
	}

	for _, route := range routesTo(machine, p.config.Routes) {
		if route.IsTCP() {
			continue
		}

		cachedPaths := p.cache.GetCachedPathsForRoute(route.Name)
		if len(cachedPaths) == 0 {
			continue
		}

		routeURL, err := url.Parse(route.Destination)
		if err != nil {
			continue
		}

		for _, path := range cachedPaths {
			select {
			case <-ctx.Done():
				p.logger.Debug("Cache warmup cancelled for machine: %s", machine.Name)
				return
			case <-time.After(100 * time.Millisecond):
			}

			reqURL := *routeURL
			reqURL.Path = path

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
			if err != nil {
				p.logger.Error("Failed to create request for %s %s: %v", machine.Name, path, err)
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				p.logger.Error("Failed to warm cache for %s %s: %v", machine.Name, path, err)
				continue
			}

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				body, err := io.ReadAll(io.LimitReader(resp.Body, p.config.CacheMaxResponseSize))
				resp.Body.Close()

				if err == nil {
					p.cache.Save(route.Name, path, resp.StatusCode, resp.Header, body)
				}
			} else {
				resp.Body.Close()
			}
		}
	}

	p.logger.Debug("Cache warmup completed for machine: %s", machine.Name)
}

func (p *ProxyService) startCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.cache.Cleanup()
		}
	}
}

func (p *ProxyService) startCacheWarming(ctx context.Context) {
	ticker := time.NewTicker(p.config.CacheWarmInterval)
	defer ticker.Stop()

	for _, machine := range p.config.Machines {
		machine.mu.RLock()
		isHealthy := machine.IsHealthy
		machine.mu.RUnlock()
		if isHealthy {
			p.warmMachine(machine)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, machine := range p.config.Machines {
				machine.mu.RLock()
				isHealthy := machine.IsHealthy
				machine.mu.RUnlock()

				if isHealthy {
					p.warmMachine(machine)
				}
			}
		}
	}
}

func isSecureServer(config *ProxyConfig) bool {
	return config.SSLCertificate != "" && config.SSLCertificateKey != ""
}

func (p *ProxyService) Start(ctx context.Context) error {
	// Start background health checks
	p.healthChecker.StartBackgroundChecks(
		ctx,
		p.config.Machines,
		p.config.Routes,
		p.config.HealthCheckInterval,
	)

	// Wait for initial health checks to complete
	p.logger.Info("Waiting for initial health checks to complete...")
	if err := p.healthChecker.WaitForInitialChecks(ctx); err != nil {
		return fmt.Errorf("initial health checks failed: %w", err)
	}

	// Start background inactivity monitor
	go p.startInactivityMonitor(ctx)

	if p.cache != nil {
		p.logger.Info("Cache enabled, root path: %s, TTL: %v, warm interval: %v",
			p.config.CacheRootPath, p.config.CacheTTL, p.config.CacheWarmInterval)
		go p.startCacheCleanup(ctx)
		go p.startCacheWarming(ctx)
	}

	p.logger.Info("Initial health checks completed, starting HTTP server")

	// Log configured routes
	for _, route := range p.config.Routes {
		p.logger.Info("Configured route: %s -> %s (%s)",
			route.Name, route.Machine.Name, route.Destination)
	}

	// A failure in any one server winds down the rest, so that the first real error
	// is what Start reports rather than whichever goroutine happens to notice the
	// shutdown first.
	ctx, cancelServers := context.WithCancel(ctx)
	defer cancelServers()

	// Bind every TCP route before serving anything, so a port clash is reported at
	// startup rather than leaving the proxy half up.
	errs := make(chan error, len(p.config.Routes)+1)
	servers := 0
	for _, route := range p.config.Routes {
		if !route.IsTCP() {
			continue
		}

		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", route.ListenPort))
		if err != nil {
			return fmt.Errorf("could not listen on port %d for machine %s: %w",
				route.ListenPort, route.Machine.Name, err)
		}
		defer listener.Close()

		servers++
		go func(listener net.Listener, route *Route) {
			errs <- p.serveTCPRoute(ctx, listener, route)
		}(listener, route)
	}

	// Start HTTP/HTTPS server
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	server := &http.Server{
		Addr:              p.config.Port,
		Handler:           mux,
		ReadTimeout:       p.config.ServerReadTimeout,
		WriteTimeout:      p.config.ServerWriteTimeout,
		IdleTimeout:       p.config.ServerIdleTimeout,
		ReadHeaderTimeout: p.config.RequestHeaderTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	httpListener, err := net.Listen("tcp", p.config.Port)
	if err != nil {
		return fmt.Errorf("could not listen on %s: %w", p.config.Port, err)
	}

	servers++
	go func() { errs <- p.serveHTTP(ctx, server, httpListener) }()

	// Wait for every server, not just the first to finish. serveTCPRoute returns nil
	// microseconds after cancellation, while serveHTTP is still draining in-flight
	// requests for up to shutdownGrace; returning on that first nil would cut every
	// response that the drain exists to protect.
	var firstErr error
	for i := 0; i < servers; i++ {
		if err := <-errs; err != nil && firstErr == nil {
			firstErr = err
			cancelServers()
		}
	}

	if p.cache != nil {
		p.cache.Close()
	}
	return firstErr
}

// serveHTTP serves until the context is cancelled, then drains in-flight requests
// before returning. A clean shutdown is not an error.
//
// server.Shutdown closes the listener first, which unblocks server.Serve() with
// http.ErrServerClosed while Shutdown is still waiting on active handlers.
// Returning on ErrServerClosed alone would let main exit before the grace window
// finishes and cut every in-flight response, so wait for the shutdown goroutine
// too.
func (p *ProxyService) serveHTTP(ctx context.Context, server *http.Server, listener net.Listener) error {
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			server.Close()
		}
	}()

	err := p.serveOn(server, listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return err
}

func (p *ProxyService) serveOn(server *http.Server, listener net.Listener) error {
	if isSecureServer(p.config) {
		// Use HTTPS when both certificate and key are provided
		tlsConfig := &tls.Config{
			Certificates: make([]tls.Certificate, 1),
		}

		cert, err := tls.LoadX509KeyPair(p.config.SSLCertificate, p.config.SSLCertificateKey)
		if err != nil {
			return fmt.Errorf("failed to load SSL certificate: %w", err)
		}
		tlsConfig.Certificates[0] = cert
		server.TLSConfig = tlsConfig

		p.logger.Info("HTTPS server listening on %s with SSL certificates", listener.Addr())
		//The files in these methods are ignored since there is already a certificate in the config.
		return server.ServeTLS(listener, "", "")
	} else {
		p.logger.Info("HTTP server listening on %s", listener.Addr())
		return server.Serve(listener)
	}
}

// clientAddr describes where a request came from, for the log. RemoteAddr is the
// peer that actually opened the connection, which is the fronting reverse proxy
// when there is one, so an X-Forwarded-For it set is reported alongside RemoteAddr
// rather than in place of it. That header is written by the caller and is only as
// trustworthy as the hop that wrote it — fine for reading logs, not for decisions.
// When the network provides PTR records (client_hostname_lookup), the peer's
// reverse-DNS hostname is reported alongside the address as well.
func (p *ProxyService) clientAddr(r *http.Request) string {
	addr := r.RemoteAddr
	if host, ok := p.clientResolver.resolve(clientIP(addr)); ok {
		addr = fmt.Sprintf("%s (hostname: %s)", addr, host)
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return fmt.Sprintf("%s (forwarded for %s)", addr, forwarded)
	}
	return addr
}

// clientIP extracts the bare IP from an "ip:port" remote address.
func clientIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// clientResolver performs best-effort reverse DNS lookups for client IPs so
// that incoming requests can be logged with the client's hostname when the
// network provides PTR records. Results (including failures) are cached, so
// each unique IP triggers at most one lookup per TTL window.
type clientResolver struct {
	enabled  bool
	ttl      time.Duration // how long a successful lookup is trusted
	negTTL   time.Duration // how long a failed lookup is remembered
	timeout  time.Duration // max wait for a single lookup
	lookupFn func(ip string, timeout time.Duration) (string, error)

	mu    sync.RWMutex
	cache map[string]clientHostEntry
}

type clientHostEntry struct {
	hostname   string // empty for failed lookups
	resolvedAt time.Time
}

func newClientResolver(enabled bool) *clientResolver {
	return &clientResolver{
		enabled:  enabled,
		ttl:      30 * time.Minute,
		negTTL:   2 * time.Minute,
		timeout:  time.Second,
		lookupFn: lookupClientAddr,
		cache:    make(map[string]clientHostEntry),
	}
}

// resolve returns the reverse DNS hostname for ip, or ("", false) when no
// name is known (or when the resolver is disabled). A lookup never blocks
// longer than r.timeout.
func (r *clientResolver) resolve(ip string) (string, bool) {
	if !r.enabled || ip == "" {
		return "", false
	}
	if host, ok := r.cached(ip); ok {
		return host, host != ""
	}

	host, err := r.lookupFn(ip, r.timeout)
	if err != nil {
		r.store(ip, "")
		return "", false
	}
	host = strings.TrimSuffix(host, ".") // drop FQDN trailing dot
	r.store(ip, host)
	return host, true
}

func (r *clientResolver) cached(ip string) (string, bool) {
	r.mu.RLock()
	entry, ok := r.cache[ip]
	r.mu.RUnlock()
	if !ok {
		return "", false
	}
	ttl := r.ttl
	if entry.hostname == "" {
		ttl = r.negTTL
	}
	if time.Since(entry.resolvedAt) > ttl {
		return "", false
	}
	return entry.hostname, true
}

func (r *clientResolver) store(ip, host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Prune expired entries as a safety net for long-running processes so
	// the cache stays bounded even with many distinct client IPs.
	if len(r.cache) > 8192 {
		now := time.Now()
		for k, e := range r.cache {
			ttl := r.ttl
			if e.hostname == "" {
				ttl = r.negTTL
			}
			if now.Sub(e.resolvedAt) > ttl {
				delete(r.cache, k)
			}
		}
	}
	r.cache[ip] = clientHostEntry{hostname: host, resolvedAt: time.Now()}
}

// lookupClientAddr performs a reverse DNS lookup with a hard timeout.
// net.LookupAddr does not accept a context, so it runs in a goroutine and
// the deadline is enforced with time.After; a timed-out lookup is reported
// as an error and the goroutine finishes on its own.
func lookupClientAddr(ip string, timeout time.Duration) (string, error) {
	type result struct {
		names []string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		ch <- result{names, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return "", res.err
		}
		for _, name := range res.names {
			if name != "" {
				return name, nil
			}
		}
		return "", fmt.Errorf("no PTR record for %s", ip)
	case <-time.After(timeout):
		return "", fmt.Errorf("reverse lookup for %s timed out after %s", ip, timeout)
	}
}

func (p *ProxyService) handleRequest(w http.ResponseWriter, r *http.Request) {
	route := p.routeForRequest(r)

	if route == nil {
		p.logger.Error("No route found for hostname: %s", r.Host)
		http.Error(w, "No route configured for this hostname", http.StatusNotFound)
		return
	}

	machineState := route.Machine
	machineName := machineState.Name

	p.logger.Info("Incoming request for hostname: %s -> machine: %s, path: %s, client: %s",
		r.Host, machineName, r.URL.Path, p.clientAddr(r))

	// Check if we have fresh health data
	cached, reason := p.healthCacheStatus(machineState)
	if cached {
		p.logger.Info("Machine %s is healthy, proxying immediately", machineName)
		p.serveWhenReady(w, r, route)
		return
	}

	// The machine looks down: before waking it, see whether the static cache
	// can answer. A cached response means the client gets a full answer
	// while the machine stays asleep.
	if p.cache != nil && r.Method == http.MethodGet {
		if resp, ok := p.cache.Get(route.Name, r.URL.Path); ok {
			p.logger.Info("Serving cached response for %s %s (machine %s is down)",
				r.Method, r.URL.Path, machineName)
			for k, v := range resp.Header {
				for _, header := range v {
					w.Header().Add(k, header)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			resp.Body.Close()
			return
		}
	}

	// Need to wake up the server
	p.logger.Info("Machine %s appears down (%s), waking for %s", machineName, reason, route.Name)
	p.healthChecker.CloseIdleConnections()
	if err := p.wakeAndWait(r.Context(), machineState); err != nil {
		p.logger.Error("Failed to wake machine %s: %v", machineName, err)
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	p.logger.Info("Machine %s is now healthy, proxying request", machineName)
	p.serveWhenReady(w, r, route)
}

// serveWhenReady gates forwarding on the route's own readiness. A machine can be
// awake seconds before the service behind a route accepts connections, and
// forwarding into that gap turns a successful wake into a 502.
func (p *ProxyService) serveWhenReady(w http.ResponseWriter, r *http.Request, route *Route) {
	cached, reason := p.readyCacheStatus(route)
	if cached {
		p.proxyRequest(w, r, route)
		return
	}

	p.logger.Info("Route %s not ready (%s), waiting", route.Name, reason)
	if err := p.waitForReady(r.Context(), route); err != nil {
		p.logger.Error("Route %s did not become ready: %v", route.Name, err)
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	p.proxyRequest(w, r, route)
}

func (p *ProxyService) readyCacheStatus(route *Route) (cached bool, reason string) {
	route.mu.RLock()
	defer route.mu.RUnlock()

	if !route.IsReady {
		if route.LastCheck.IsZero() {
			return false, "no prior readiness check"
		}
		return false, fmt.Sprintf("marked unready (last check %v ago)",
			p.clock.Now().Sub(route.LastCheck).Round(time.Second))
	}

	age := p.clock.Now().Sub(route.LastCheck)
	if age > p.config.HealthCacheDuration {
		return false, fmt.Sprintf("cached readiness expired (last check %v ago)", age.Round(time.Second))
	}

	return true, ""
}

func (p *ProxyService) waitForReady(ctx context.Context, route *Route) error {
	// Check before waiting on a tick. A cached readiness result expires well before
	// the next background sweep refreshes it, so most requests that land here are for
	// routes that are in fact ready and should not pay a poll interval of latency.
	if p.markReadyIfHealthy(ctx, route) {
		return nil
	}

	timeout := p.clock.After(p.config.Timeout)
	ticker := p.clock.NewTicker(p.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for route %s to become ready after %v",
				route.Name, p.config.Timeout)
		case <-ticker.C():
			if p.markReadyIfHealthy(ctx, route) {
				return nil
			}
		}
	}
}

func (p *ProxyService) markReadyIfHealthy(ctx context.Context, route *Route) bool {
	if !p.healthChecker.Check(ctx, route.HealthCheck, "readiness") {
		return false
	}

	route.mu.Lock()
	route.IsReady = true
	route.LastCheck = p.clock.Now()
	route.mu.Unlock()
	return true
}

func (p *ProxyService) routeForRequest(r *http.Request) *Route {
	// Remove port from host if present
	host := r.Host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	return p.config.RoutesByHostname[host]
}

func (p *ProxyService) healthCacheStatus(machine *Machine) (cached bool, reason string) {
	machine.mu.RLock()
	defer machine.mu.RUnlock()

	if !machine.IsHealthy {
		if machine.LastCheck.IsZero() {
			return false, "no prior health check"
		}
		return false, fmt.Sprintf(
			"marked unhealthy (last check %v ago)",
			p.clock.Now().Sub(machine.LastCheck).Round(time.Second),
		)
	}

	age := p.clock.Now().Sub(machine.LastCheck)
	if age > p.config.HealthCacheDuration {
		return false, fmt.Sprintf(
			"cached health expired (last check %v ago, cache duration %v)",
			age.Round(time.Second), p.config.HealthCacheDuration,
		)
	}

	return true, ""
}

// defaultWOLBurstCount is how many magic packets a burst carries when the
// machine does not configure wol_burst_count. A single packet is easy to lose
// to a sleeping NIC or a switch that has not refreshed its ARP entry yet, so
// each wake cycle sends a short burst instead.
const defaultWOLBurstCount = 3

// wakeAndWait makes sure a wake is in flight for the machine, then makes the
// caller wait for its outcome bounded by the caller's ctx. The wake itself is
// owned by the proxy, not by any request: it runs in its own goroutine on a
// background context (see runWake), so it keeps going even if the client that
// triggered it - or every client - times out, disconnects, or the proxy is
// asked to shut down. All requests (the one that started the wake and any
// that join it) merely wait on the shared completion channel of the same wake
// generation; a client that leaves only stops waiting, it never cancels the
// wake.
func (p *ProxyService) wakeAndWait(ctx context.Context, machine *Machine) error {
	var info *wakeInfo
	machine.mu.Lock()
	if machine.IsWaking {
		info = machine.wake
		machine.mu.Unlock()
		p.logger.Info("Machine %s wake already in progress, joining existing wait (gen=%d)",
			machine.Name, info.gen)
	} else {
		machine.wakeGen++
		machine.IsWaking = true
		machine.LastActivity = p.clock.Now()
		info = &wakeInfo{gen: machine.wakeGen, done: make(chan struct{})}
		machine.wake = info
		machine.mu.Unlock()

		p.logger.Info("Machine %s is down, starting wake (gen=%d)", machine.Name, info.gen)
		go p.runWake(machine, info)
	}
	return p.joinWake(ctx, machine, info)
}

// runWake performs the actual wake (WOL bursts + health polling) for one
// generation, fully detached from any request context. Clients routinely time
// out long before a machine can boot, so the wake must outlive them: it runs
// on a fresh background context bounded only by the (per-machine) wake
// timeout, and it always reaches finishWake, which releases every waiter and
// clears IsWaking. The first burst packet goes out immediately; waitForWake
// owns all packet sending.
func (p *ProxyService) runWake(machine *Machine, info *wakeInfo) {
	p.logger.Info("WOL wake started for %s (gen=%d)", machine.Name, info.gen)

	wakeCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.finishWake(machine, info, p.waitForWake(wakeCtx, machine, info.gen))
}

// finishWake publishes the outcome of a wake generation, clears IsWaking and
// releases every waiter in one critical section, so no new wake generation
// can start in between the state update and the close of done: joiners that
// wake up on done always observe the result of the generation they joined.
func (p *ProxyService) finishWake(machine *Machine, info *wakeInfo, err error) {
	machine.mu.Lock()
	if machine.wakeGen == info.gen {
		machine.IsWaking = false
	}
	info.err = err
	machine.mu.Unlock()
	close(info.done)
}

// joinWake makes a request wait for one wake generation to finish, bounded by
// the request's ctx. A result of ctx.Err() only means "this client stopped
// waiting"; the wake itself keeps running (runWake is detached from the
// request), so the machine is still confirmed even if every client gave up.
func (p *ProxyService) joinWake(ctx context.Context, machine *Machine, info *wakeInfo) error {
	if info == nil {
		return fmt.Errorf("no in-flight wake to join for %s", machine.Name)
	}

	select {
	case <-info.done:
		// finishWake published info.err in the same critical section that
		// cleared IsWaking, before closing done: it always describes this
		// generation, even if a new wake has already started meanwhile.
		machine.mu.RLock()
		healthy := machine.IsHealthy
		machine.mu.RUnlock()
		if healthy {
			return nil
		}
		if info.err != nil {
			return info.err
		}
		return fmt.Errorf("wake failed for %s", machine.Name)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitForWake repeatedly sends a burst of WOL packets and waits for the
// machine to come up. Each cycle is strictly: send a burst of burstCount
// packets 500ms apart, THEN wait the full waitDuration, and only THEN perform
// a single health check. Checking health immediately after a burst is
// pointless - the machine hasn't had time to boot - so no check happens until
// the full wait has elapsed.
//
// The first wait starts at startup_time (a machine that just got its WOL
// packet cannot answer a health check yet). The interval between subsequent
// checks is either:
//   - adaptive (default): halved on every retry, floored at 500ms
//     (30s, 15s, 7.5s, ...), which converges quickly once the machine is
//     close to being up; or
//   - fixed: the machine's wake_health_check_interval (e.g. 2s), which spots
//     a booted machine within one interval (also floored at 500ms).
//
// The whole operation is bounded by the machine's wake timeout (its
// wake_timeout, or the global timeout when the machine does not override it) -
// deliberately independent of any client request's deadline.
func (p *ProxyService) waitForWake(ctx context.Context, machine *Machine, wakeGen int) error {
	wakeTimeout := p.config.Timeout
	if machine.Config.WakeTimeout > 0 {
		wakeTimeout = machine.Config.WakeTimeout
	}
	checkInterval := machine.Config.WakeHealthCheckInterval

	timeout := p.clock.After(wakeTimeout)
	wakeStartTime := p.clock.Now()
	waitDuration := p.config.StartupTime

	burstCount := defaultWOLBurstCount
	if machine.Config.WolBurstCount != 0 {
		burstCount = machine.Config.WolBurstCount
		if burstCount < 1 {
			burstCount = 1
		} else if burstCount > 10 {
			burstCount = 10
		}
	}
	burstInterval := 500 * time.Millisecond

	// sendWOLBurst sends burstCount WOL packets burstInterval apart. It
	// returns early (with the cancellation cause) if the context is
	// cancelled or the wake times out mid-burst.
	sendWOLBurst := func() error {
		for i := 0; i < burstCount; i++ {
			if err := p.wolSender.SendWOL(
				machine.Config.MacAddress,
				machine.Config.BroadcastIP,
				machine.Config.WolPort,
			); err != nil {
				p.logger.Error("Failed to send WOL packet during burst: %v", err)
			} else {
				p.logger.Info("Sent WOL burst packet %d/%d to %s",
					i+1, burstCount, machine.Name)
			}
			if i < burstCount-1 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timeout:
					return fmt.Errorf("timeout waiting for %s to wake up after %v",
						machine.Name, wakeTimeout)
				case <-p.clock.After(burstInterval):
				}
			}
		}
		return nil
	}

	for {
		if err := sendWOLBurst(); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for %s to wake up after %v",
				machine.Name, wakeTimeout)
		case <-p.clock.After(waitDuration):
		}

		if p.healthChecker.Check(ctx, machine.Config.HealthCheck, "wake") {
			machine.mu.Lock()
			machine.IsHealthy = true
			machine.LastCheck = p.clock.Now()
			machine.mu.Unlock()

			wakeDuration := p.clock.Now().Sub(wakeStartTime)
			p.logger.Info("Machine %s woke up after %v (gen=%d)",
				machine.Name, wakeDuration, wakeGen)

			if p.cache != nil {
				// Refresh the cached paths now that the machine is
				// reachable again. Only invalidating the cache and
				// relying on the next warm tick (up to warm_interval
				// later) or a future proxied GET to repopulate it means
				// a machine that sleeps again before either happens
				// falls back to triggering WOL on every cached request.
				// Refreshing in place (instead of deleting first) also
				// keeps the previous entries servable if the refresh
				// itself fails.
				go p.warmMachine(machine)
			}
			return nil
		}

		if checkInterval > 0 {
			if checkInterval < 500*time.Millisecond {
				checkInterval = 500 * time.Millisecond
			}
			waitDuration = checkInterval
		} else {
			waitDuration = waitDuration / 2
			if waitDuration < 500*time.Millisecond {
				waitDuration = 500 * time.Millisecond
			}
		}
	}
}

// serveTCPRoute accepts connections on listener and forwards each to the route's
// destination, waking the machine first if it is asleep. It returns when ctx is
// cancelled or the listener stops accepting.
func (p *ProxyService) serveTCPRoute(ctx context.Context, listener net.Listener, route *Route) error {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	p.logger.Info("Listening on %s for machine %s -> %s",
		listener.Addr(), route.Machine.Name, route.Destination)

	delay := time.Duration(0)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !isTemporaryAcceptError(err) {
				return fmt.Errorf("accept on %s failed: %w", listener.Addr(), err)
			}

			// Back off rather than spinning, and keep serving: this route failing
			// hard would propagate to main and take every other route down with it.
			if delay == 0 {
				delay = acceptRetryDelayMin
			} else {
				delay *= 2
			}
			if delay > acceptRetryDelayMax {
				delay = acceptRetryDelayMax
			}
			p.logger.Error("Accept on %s failed (%v), retrying in %v",
				listener.Addr(), err, delay)

			select {
			case <-p.clock.After(delay):
			case <-ctx.Done():
				return nil
			}
			continue
		}

		delay = 0
		go p.forwardTCPConn(ctx, conn, route)
	}
}

// forwardTCPConn wakes the machine if needed, then splices the accepted connection
// to the destination. The client is already connected while we wake, so it waits on
// the upstream's protocol banner rather than on connect — an ssh client with a short
// ConnectTimeout still gets through a slow wake.
func (p *ProxyService) forwardTCPConn(ctx context.Context, client net.Conn, route *Route) {
	defer client.Close()

	machine := route.Machine
	if cached, reason := p.healthCacheStatus(machine); !cached {
		p.logger.Info("Machine %s appears down (%s), waking for %s", machine.Name, reason, route.Name)
		if err := p.wakeAndWait(ctx, machine); err != nil {
			p.logger.Error("Failed to wake machine %s for %s: %v", machine.Name, route.Name, err)
			return
		}
	}

	if cached, reason := p.readyCacheStatus(route); !cached {
		p.logger.Info("Route %s not ready (%s), waiting before forwarding", route.Name, reason)
		if err := p.waitForReady(ctx, route); err != nil {
			p.logger.Error("Route %s did not become ready: %v", route.Name, err)
			return
		}
	}

	dialer := net.Dialer{Timeout: p.config.Timeout}
	upstream, err := dialer.DialContext(ctx, "tcp", route.Destination)
	if err != nil {
		p.logger.Error("Could not reach %s for route %s: %v", route.Destination, route.Name, err)
		return
	}
	defer upstream.Close()

	machine.mu.Lock()
	machine.LastActivity = p.clock.Now()
	machine.mu.Unlock()

	machine.holdConnection()
	defer func() { machine.releaseConnection(p.clock.Now()) }()

	// Both directions must finish before the deferred closes run. A client that
	// half-closes its write side — ssh and scp both do, once the request is sent —
	// ends one direction while the response is still streaming back on the other.
	var copies sync.WaitGroup
	copies.Add(2)
	splice := func(dst, src net.Conn) {
		defer copies.Done()
		io.Copy(dst, src)
		// Half-close so the peer sees EOF while the other direction still drains.
		if conn, ok := dst.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
	}
	go splice(upstream, client)
	go splice(client, upstream)

	done := make(chan struct{})
	go func() {
		copies.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (p *ProxyService) proxyRequest(w http.ResponseWriter, r *http.Request, route *Route) {
	machineState := route.Machine
	machineState.mu.Lock()
	machineState.LastActivity = p.clock.Now()
	machineState.mu.Unlock()

	// A slow upload or download can outlast the inactivity threshold; hold the
	// machine for as long as the request is in flight.
	machineState.holdConnection()
	defer func() { machineState.releaseConnection(p.clock.Now()) }()

	targetURL, err := url.Parse(route.Destination)
	if err != nil {
		p.logger.Error("Invalid target URL %s: %v", route.Destination, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Create a custom transport with optimized settings for large uploads
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second, // Increased timeout for slow connections
			KeepAlive: 60 * time.Second, // Increased keep-alive
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       120 * time.Second, // Increased idle timeout
		TLSHandshakeTimeout:   20 * time.Second,  // Increased TLS handshake timeout
		ExpectContinueTimeout: 5 * time.Second,   // Increased expect-continue timeout
		MaxIdleConnsPerHost:   10,
		// Disable compression to avoid issues with already compressed data
		DisableCompression:    true,
		ResponseHeaderTimeout: p.config.ResponseHeaderTimeout,
		// No timeout for reading the entire response
		ReadBufferSize:  1024 * 1024, // 1MB buffer for reading
		WriteBufferSize: 1024 * 1024, // 1MB buffer for writing
	}

	// Customize the proxy to handle errors and logging
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Set the Host header to the target's hostname from the URL
		req.Host = targetURL.Host

		// Log request details including content length for debugging
		contentLength := req.ContentLength
		contentType := req.Header.Get("Content-Type")
		p.logger.Info("Proxying %s %s to %s (Host: %s, Content-Length: %d, Content-Type: %s)",
			req.Method, req.URL.Path, targetURL, req.Host, contentLength, contentType)

		// For large uploads, add special handling
		if contentLength > 1024*1024 { // If larger than 1MB
			p.logger.Info("Large upload detected (%d bytes) for %s %s",
				contentLength, req.Method, req.URL.Path)
		}
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		p.logger.Error("Proxy error for %s (%s): %v", route.Machine.Name, route.Hostname, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}

	// Disable buffering of response body for streaming uploads/downloads
	proxy.ModifyResponse = func(resp *http.Response) error {
		p.logger.Info("Response from %s: status=%d, content-length=%d",
			route.Name, resp.StatusCode, resp.ContentLength)

		if p.cache != nil && r.Method == http.MethodGet && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			cachePaths, exists := p.config.CacheRoutes[route.Name]
			if exists {
				var shouldCache bool
				for _, pattern := range cachePaths {
					if strings.HasSuffix(pattern, "/*") {
						prefix := strings.TrimSuffix(pattern, "/*")
						if strings.HasPrefix(r.URL.Path, prefix) {
							shouldCache = true
							break
						}
					} else if r.URL.Path == pattern {
						shouldCache = true
						break
					}
				}

				if shouldCache {
					buf := &bytes.Buffer{}
					tee := io.TeeReader(resp.Body, buf)
					resp.Body = &catchingBody{
						Reader:   tee,
						original: resp.Body,
						onDone: func() {
							body := buf.Bytes()
							if int64(len(body)) <= p.config.CacheMaxResponseSize {
								p.cache.Save(route.Name, r.URL.Path, resp.StatusCode, resp.Header, body)
							}
						},
					}
				}
			}
		}

		return nil
	}

	proxy.ServeHTTP(w, r)
}

// Config loader
func LoadConfig(filename string, clock Clock) (*ProxyConfig, error) {
	var config Config
	meta, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return nil, err
	}

	// A key the struct does not claim is almost always a typo, and decoding leaves
	// the field at its zero value — which is how a config ends up with, say, no
	// health check at all and no hint as to why. Refuse rather than run degraded.
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return nil, fmt.Errorf("unknown key(s) in %s: %s", filename, strings.Join(keys, ", "))
	}

	// Trim whitespace and handle optional SSL certificate fields
	config.SSLCertificate = strings.TrimSpace(config.SSLCertificate)
	config.SSLCertificateKey = strings.TrimSpace(config.SSLCertificateKey)

	// Set defaults
	if config.Port == "" {
		config.Port = ":8080"
	}
	if !strings.HasPrefix(config.Port, ":") {
		config.Port = ":" + config.Port
	}

	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	// startup_time is the quiet period between the first WOL packet and the
	// first health check: a machine that was just sent a magic packet cannot
	// answer one yet. It must fit inside each machine's wake budget (its
	// wake_timeout, or the global timeout), or the wake times out before it
	// ever checks.
	startupTime := 30 * time.Second
	if config.StartupTime != "" {
		startupTime, err = time.ParseDuration(config.StartupTime)
		if err != nil {
			return nil, fmt.Errorf("invalid startup_time: %w", err)
		}
	}

	if config.RequestHeaderTimeout == "" {
		config.RequestHeaderTimeout = "30s"
	}
	requestHeaderTimeout, err := time.ParseDuration(config.RequestHeaderTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid request_header_timeout: %w", err)
	}

	if config.ResponseHeaderTimeout == "" {
		config.ResponseHeaderTimeout = "1m"
	}
	responseHeaderTimeout, err := time.ParseDuration(config.ResponseHeaderTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid response_header_timeout: %w", err)
	}

	if config.ServerReadTimeout == "" {
		config.ServerReadTimeout = "10m"
	}
	serverReadTimeout, err := time.ParseDuration(config.ServerReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid server_read_timeout: %w", err)
	}

	if config.ServerWriteTimeout == "" {
		config.ServerWriteTimeout = "10m"
	}
	serverWriteTimeout, err := time.ParseDuration(config.ServerWriteTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid server_write_timeout: %w", err)
	}

	if config.ServerIdleTimeout == "" {
		config.ServerIdleTimeout = "120s"
	}
	serverIdleTimeout, err := time.ParseDuration(config.ServerIdleTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid server_idle_timeout: %w", err)
	}

	pollInterval, err := time.ParseDuration(config.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid poll_interval: %w", err)
	}

	healthCheckInterval, err := time.ParseDuration(config.HealthCheckInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid health_check_interval: %w", err)
	}

	healthCacheDuration, err := time.ParseDuration(config.HealthCacheDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid health_cache_duration: %w", err)
	}

	var cacheEnabled bool
	var cacheRootPath string
	var cacheTTL time.Duration
	var cacheMaxResponseSize int64
	var cacheWarmInterval time.Duration
	cacheRoutes := make(map[string][]string)

	if config.CacheConfig.Enabled {
		cacheEnabled = true
		cacheRootPath = config.CacheConfig.RootPath
		if cacheRootPath == "" {
			cacheRootPath = "./cache"
		}

		cacheTTL = 24 * time.Hour
		if config.CacheConfig.TTL != "" {
			cacheTTL, err = time.ParseDuration(config.CacheConfig.TTL)
			if err != nil {
				return nil, fmt.Errorf("invalid cache ttl: %w", err)
			}
		}

		cacheMaxResponseSize = 10 * 1024 * 1024
		if config.CacheConfig.MaxResponseSizeBytes > 0 {
			cacheMaxResponseSize = config.CacheConfig.MaxResponseSizeBytes
		}

		cacheWarmInterval = 30 * time.Minute
		if config.CacheConfig.WarmInterval != "" {
			cacheWarmInterval, err = time.ParseDuration(config.CacheConfig.WarmInterval)
			if err != nil {
				return nil, fmt.Errorf("invalid cache warm_interval: %w", err)
			}
		}

		for _, cr := range config.CacheConfig.Routes {
			cacheRoutes[cr.Route] = cr.Paths
		}
	}

	// client_hostname_lookup is optional; unset means enabled.
	clientHostnameLookup := true
	if config.ClientHostnameLookup != nil {
		clientHostnameLookup = *config.ClientHostnameLookup
	}

	if len(config.Targets) > 0 && (len(config.Machines) > 0 || len(config.Routes) > 0) {
		return nil, fmt.Errorf("config mixes the legacy [[targets]] format with [[machines]]/[[routes]]; use one or the other")
	}

	machineEntries, routeEntries := config.Machines, config.Routes
	fromLegacy := len(config.Targets) > 0
	if fromLegacy {
		machineEntries, routeEntries = migrateLegacyTargets(config.Targets)
	}

	model, err := buildMachinesAndRoutes(machineEntries, routeEntries, clock, fromLegacy)
	if err != nil {
		return nil, err
	}

	// A cache block naming a route that does not exist is a typo that would
	// otherwise silently cache nothing. TCP routes carry no HTTP semantics,
	// so they cannot be cached either.
	for _, cr := range config.CacheConfig.Routes {
		found := false
		for _, route := range model.routes {
			if route.Name == cr.Route {
				if route.IsTCP() {
					return nil, fmt.Errorf("cache route %q is a TCP route; only HTTP routes can be cached", cr.Route)
				}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("cache references unknown route %q", cr.Route)
		}
	}

	// startup_time must fit inside each machine's effective wake budget: its
	// own wake_timeout when set, the global timeout otherwise.
	for _, m := range model.machines {
		if m.Config.WakeTimeout > 0 {
			if startupTime >= m.Config.WakeTimeout {
				return nil, fmt.Errorf("startup_time (%v) must be less than wake_timeout (%v) for machine %s",
					startupTime, m.Config.WakeTimeout, m.Name)
			}
		} else if startupTime >= timeout {
			return nil, fmt.Errorf("startup_time (%v) must be less than timeout (%v)", startupTime, timeout)
		}
	}

	return &ProxyConfig{
		Port:                  config.Port,
		SSLCertificate:        config.SSLCertificate,
		SSLCertificateKey:     config.SSLCertificateKey,
		Timeout:               timeout,
		StartupTime:           startupTime,
		RequestHeaderTimeout:  requestHeaderTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ServerReadTimeout:     serverReadTimeout,
		ServerWriteTimeout:    serverWriteTimeout,
		ServerIdleTimeout:     serverIdleTimeout,
		ClientHostnameLookup:  clientHostnameLookup,
		PollInterval:          pollInterval,
		HealthCheckInterval:   healthCheckInterval,
		HealthCacheDuration:   healthCacheDuration,
		Machines:              model.machines,
		Routes:                model.routes,
		RoutesByHostname:      model.byHostname,
		RoutesByListenPort:    model.byListenPort,
		CacheEnabled:          cacheEnabled,
		CacheRootPath:         cacheRootPath,
		CacheTTL:              cacheTTL,
		CacheMaxResponseSize:  cacheMaxResponseSize,
		CacheWarmInterval:     cacheWarmInterval,
		CacheRoutes:           cacheRoutes,
	}, nil
}

// defaultHealthCheckForDestination derives a route's readiness check from where it
// forwards to: dialing the destination is free, since the proxy is about to connect
// there anyway. HTTP destinations are URLs and may leave the port implicit; TCP
// destinations are already host:port.
func defaultHealthCheckForDestination(destination string) (string, error) {
	if !strings.Contains(destination, "://") {
		if _, _, err := net.SplitHostPort(destination); err != nil {
			return "", fmt.Errorf("destination %q must be host:port or a URL: %w", destination, err)
		}
		return tcpScheme + destination, nil
	}

	parsed, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("invalid destination %q: %w", destination, err)
	}

	host, port := parsed.Hostname(), parsed.Port()
	if host == "" {
		return "", fmt.Errorf("destination %q has no host", destination)
	}
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}

	return tcpScheme + net.JoinHostPort(host, port), nil
}

// MigrateConfigFile writes the machines + routes translation of a legacy config
// next to the original, so an operator can adopt it with a single mv. The original
// is never touched: it is often bind-mounted read-only or checked into a config
// repo, and rewriting it would silently drop every comment. If the sidecar cannot
// be written, the translation is logged instead so nothing is lost.
func MigrateConfigFile(path string, logger Logger) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return
	}
	if len(config.Targets) == 0 {
		return
	}

	config.Machines, config.Routes = migrateLegacyTargets(config.Targets)
	config.Targets = nil

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(config); err != nil {
		logger.Error("Could not translate the legacy config: %v", err)
		return
	}
	migrated := dropUnsetIntKeys(buf.String())

	ext := filepath.Ext(path)
	migratedPath := strings.TrimSuffix(path, ext) + ".migrated" + ext

	if err := os.WriteFile(migratedPath, []byte(migrated), 0o600); err != nil {
		logger.Info("This config uses the legacy [[targets]] format. Could not write %s (%v); "+
			"the migrated config follows — save it yourself:\n%s", migratedPath, err, migrated)
		return
	}

	logger.Info("This config uses the legacy [[targets]] format, which will be removed in a future "+
		"release. A migrated copy was written to %s — review it and replace your config with it.", migratedPath)
}

// dropUnsetIntKeys removes "key = 0" lines from encoded TOML. The toml encoder
// honours omitempty for strings but not for ints, and every int key in this config
// means "unset" at zero — emitting them would litter a migrated config with keys
// the operator never wrote.
func dropUnsetIntKeys(encoded string) string {
	lines := strings.Split(encoded, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasSuffix(strings.TrimSpace(line), "= 0") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// migrateLegacyTargets translates [[targets]] blocks into the machines + routes
// form. Each legacy target was a machine and a route rolled into one, so it
// becomes exactly one of each.
func migrateLegacyTargets(targets []Target) ([]MachineEntry, []RouteEntry) {
	machines := make([]MachineEntry, 0, len(targets))
	routes := make([]RouteEntry, 0, len(targets))

	for _, target := range targets {
		machines = append(machines, MachineEntry{
			Name:                 target.Name,
			MacAddress:           target.MacAddress,
			BroadcastIP:          target.BroadcastIP,
			WolPort:              target.WolPort,
			HealthCheck:          target.HealthEndpoint,
			SSHHost:              target.SSHHost,
			SSHUser:              target.SSHUser,
			SSHKeyPath:           target.SSHKeyPath,
			ShutdownCommand:      target.ShutdownCommand,
			ShutdownHTTPUrl:      target.ShutdownHTTPUrl,
			ShutdownHTTPMethod:   target.ShutdownHTTPMethod,
			ShutdownHTTPOKStatus: target.ShutdownHTTPOKStatus,
			InactivityThreshold:  target.InactivityThreshold,
		})
		routes = append(routes, RouteEntry{
			Machine:     target.Name,
			Hostname:    target.Hostname,
			Destination: target.Destination,
			// A legacy health_endpoint gated both waking and forwarding, so it
			// becomes the machine's liveness check and this route's readiness check.
			HealthCheck: target.HealthEndpoint,
		})
	}

	return machines, routes
}

// buildMachinesAndRoutes turns the machine and route blocks of a config file into
// the runtime model: one Machine per machine block, shared by every route that
// names it.
// validateDestination rejects a destination that cannot work for its route kind, at
// load time rather than on the first connection. A TCP route dials the string
// directly, so it must be host:port. An HTTP route builds a reverse proxy from it,
// and url.Parse accepts far too much: "nas.local:2342" parses as scheme "nas.local"
// with opaque body "2342" — dots are legal in scheme names — yielding a proxy that
// 502s every request with nothing in the logs to explain it.
// validateHealthCheck rejects a check the checker cannot actually perform. Check
// dispatches on the scheme — tcp:// dials, anything else is handed to an HTTP client
// — so a bare "nas.local:22" parses as a URL with scheme "nas.local" and fails every
// time, leaving the machine permanently unhealthy exactly as an empty value would.
func validateHealthCheck(label, value string) error {
	if address, ok := strings.CutPrefix(value, tcpScheme); ok {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("%s: health check %q must be tcp://host:port: %w", label, value, err)
		}
		return nil
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s: invalid health check %q: %w", label, value, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf(
			"%s: health check %q must be a tcp://, http:// or https:// URL", label, value)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s: health check %q has no host", label, value)
	}
	return nil
}

func validateDestination(name, destination string, isTCP bool) error {
	if strings.TrimSpace(destination) == "" {
		return fmt.Errorf("route %s needs a destination", name)
	}

	if isTCP {
		if _, _, err := net.SplitHostPort(destination); err != nil {
			return fmt.Errorf("route %s forwards raw TCP, so destination %q must be host:port: %w",
				name, destination, err)
		}
		return nil
	}

	parsed, err := url.Parse(destination)
	if err != nil {
		return fmt.Errorf("route %s: invalid destination %q: %w", name, destination, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("route %s proxies HTTP, so destination %q must be an http:// or https:// URL",
			name, destination)
	}
	if parsed.Host == "" {
		return fmt.Errorf("route %s: destination %q has no host", name, destination)
	}
	return nil
}

func buildMachinesAndRoutes(machineEntries []MachineEntry, routeEntries []RouteEntry, clock Clock, fromLegacy bool) (routing, error) {
	machines := make(map[string]*Machine)
	routes := make([]*Route, 0, len(routeEntries))
	routesByHostname := make(map[string]*Route)
	routesByListenPort := make(map[int]*Route)
	var err error

	for _, entry := range machineEntries {
		if entry.Name == "" {
			return routing{}, fmt.Errorf("every machine needs a name")
		}
		if _, exists := machines[entry.Name]; exists {
			return routing{}, fmt.Errorf("duplicate machine name %q", entry.Name)
		}

		// Liveness drives waking, the wake wait and the shutdown decision. Without it
		// every Check fails, the machine is permanently unhealthy, and every request
		// sprays WOL for the whole timeout before returning 503. Name the key the
		// operator actually wrote, which differs in the legacy format.
		if strings.TrimSpace(entry.HealthCheck) == "" {
			key := "health_check"
			if fromLegacy {
				key = "health_endpoint"
			}
			return routing{}, fmt.Errorf(
				"machine %s needs a %s: it is how the proxy tells whether the box is up",
				entry.Name, key)
		}
		if err := validateHealthCheck("machine "+entry.Name, entry.HealthCheck); err != nil {
			return routing{}, err
		}

		// Disallow using both SSH shutdown command and HTTP shutdown URL
		if strings.TrimSpace(entry.ShutdownHTTPUrl) != "" && strings.TrimSpace(entry.ShutdownCommand) != "" {
			return routing{}, fmt.Errorf("machine %s: cannot define both shutdown_http_url and shutdown_command; choose one", entry.Name)
		}

		// Disallow http method/ok status without URL
		if strings.TrimSpace(entry.ShutdownHTTPUrl) == "" && (strings.TrimSpace(entry.ShutdownHTTPMethod) != "" || entry.ShutdownHTTPOKStatus != 0) {
			return routing{}, fmt.Errorf("machine %s: shutdown_http_method and/or shutdown_http_ok_status require shutdown_http_url to be set", entry.Name)
		}

		var inactivityThreshold time.Duration
		if entry.InactivityThreshold != "" {
			inactivityThreshold, err = time.ParseDuration(entry.InactivityThreshold)
			if err != nil {
				return routing{}, fmt.Errorf("invalid inactivity_threshold for machine %s: %w", entry.Name, err)
			}
		}

		var wakeTimeout time.Duration
		if entry.WakeTimeout != "" {
			wakeTimeout, err = time.ParseDuration(entry.WakeTimeout)
			if err != nil {
				return routing{}, fmt.Errorf("invalid wake_timeout for machine %s: %w", entry.Name, err)
			}
		}

		var wakeHealthCheckInterval time.Duration
		if entry.WakeHealthCheckInterval != "" {
			wakeHealthCheckInterval, err = time.ParseDuration(entry.WakeHealthCheckInterval)
			if err != nil {
				return routing{}, fmt.Errorf("invalid wake_health_check_interval for machine %s: %w", entry.Name, err)
			}
		}

		if entry.WolBurstCount != 0 && (entry.WolBurstCount < 1 || entry.WolBurstCount > 10) {
			return routing{}, fmt.Errorf("wol_burst_count for machine %s must be between 1 and 10, got %d",
				entry.Name, entry.WolBurstCount)
		}

		machines[entry.Name] = &Machine{
			Name: entry.Name,
			Config: &MachineConfig{
				MacAddress:              entry.MacAddress,
				BroadcastIP:             entry.BroadcastIP,
				WolPort:                 entry.WolPort,
				WolBurstCount:           entry.WolBurstCount,
				WakeTimeout:             wakeTimeout,
				WakeHealthCheckInterval: wakeHealthCheckInterval,
				HealthCheck:             entry.HealthCheck,
				SSHHost:                 entry.SSHHost,
				SSHUser:                 entry.SSHUser,
				SSHKeyPath:              entry.SSHKeyPath,
				ShutdownCommand:         entry.ShutdownCommand,
				ShutdownHTTPUrl:         entry.ShutdownHTTPUrl,
				ShutdownHTTPMethod:      entry.ShutdownHTTPMethod,
				ShutdownHTTPOKStatus:    entry.ShutdownHTTPOKStatus,
				InactivityThreshold:     inactivityThreshold,
			},
			LastActivity: clock.Now(),
		}
	}

	for _, entry := range routeEntries {
		name := entry.Hostname
		if name == "" {
			name = fmt.Sprintf(":%d", entry.ListenPort)
		}

		switch {
		case entry.Hostname == "" && entry.ListenPort == 0:
			return routing{}, fmt.Errorf("route for machine %q needs either a hostname or a listen_port", entry.Machine)
		case entry.Hostname != "" && entry.ListenPort != 0:
			return routing{}, fmt.Errorf("route %s sets both hostname and listen_port; a route is reached one way or the other", name)
		}

		if existing, exists := routesByHostname[entry.Hostname]; exists {
			return routing{}, fmt.Errorf("duplicate hostname %s for routes to machines %s and %s",
				entry.Hostname, existing.Machine.Name, entry.Machine)
		}
		if existing, exists := routesByListenPort[entry.ListenPort]; exists {
			return routing{}, fmt.Errorf("duplicate listen_port %d for routes to machines %s and %s",
				entry.ListenPort, existing.Machine.Name, entry.Machine)
		}

		machine, exists := machines[entry.Machine]
		if !exists {
			return routing{}, fmt.Errorf("route %s references undefined machine %q", name, entry.Machine)
		}

		// Validate regardless of whether health_check was given: deriving the check
		// from the destination used to be the only thing that looked at it, so an
		// explicit health_check silently bought a pass on a broken destination.
		if err := validateDestination(name, entry.Destination, entry.ListenPort != 0); err != nil {
			return routing{}, err
		}

		healthCheck := entry.HealthCheck
		if healthCheck == "" {
			healthCheck, err = defaultHealthCheckForDestination(entry.Destination)
			if err != nil {
				return routing{}, fmt.Errorf("route %s: %w", name, err)
			}
		} else if err := validateHealthCheck("route "+name, healthCheck); err != nil {
			// Only an explicit check can be malformed; a derived one is always
			// tcp://host:port by construction.
			return routing{}, err
		}

		route := &Route{
			Name:        name,
			Machine:     machine,
			Hostname:    entry.Hostname,
			ListenPort:  entry.ListenPort,
			Destination: entry.Destination,
			HealthCheck: healthCheck,
		}
		routes = append(routes, route)
		if route.IsTCP() {
			routesByListenPort[route.ListenPort] = route
		} else {
			routesByHostname[route.Hostname] = route
		}
	}

	return routing{machines: machines, routes: routes, byHostname: routesByHostname, byListenPort: routesByListenPort}, nil
}

// Simple logger implementation
type StdLogger struct{}

func (l *StdLogger) Info(msg string, args ...interface{}) {
	log.Printf("[INFO] "+msg, args...)
}

func (l *StdLogger) Error(msg string, args ...interface{}) {
	log.Printf("[ERROR] "+msg, args...)
}

func (l *StdLogger) Debug(msg string, args ...interface{}) {
	log.Printf("[DEBUG] "+msg, args...)
}

func logStartup(logger Logger, version string) {
	logger.Info("Starting doormouse version `%s`", version)
}

// warnUnreadableSSHKeys reports SSH keys the process cannot open. The key is
// otherwise read only when a machine has gone idle, so a permissions mistake
// stays invisible until the first shutdown silently fails, up to an
// inactivity_threshold later. Only a warning: a machine may never go idle, and
// refusing to start would take the proxy down over a path it may never use.
func warnUnreadableSSHKeys(config *ProxyConfig, logger Logger) {
	for name, machine := range config.Machines {
		path := machine.Config.SSHKeyPath
		if path == "" || machine.Config.ShutdownHTTPUrl != "" {
			continue
		}
		// Non-blocking open prevents a FIFO from hanging startup, even if the
		// path is replaced concurrently. Check the opened file, not the path.
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			var info os.FileInfo
			info, err = file.Stat()
			file.Close()
			if err == nil && !info.Mode().IsRegular() {
				err = fmt.Errorf("not a regular file")
			}
		}
		if err != nil {
			logger.Error("Machine %s: cannot read ssh_key_path %s (%v). Shutting this machine "+
				"down over SSH will fail until the file is readable by the user doormouse runs as.", name, path, err)
			continue
		}
	}
}

// Main function
func main() {
	logger := &StdLogger{}
	logStartup(logger, version)

	if len(os.Args) < 2 {
		log.Fatal("Usage: doormouse <config.toml>")
	}

	configFile := os.Args[1]

	// Load configuration
	clock := RealClock{}

	MigrateConfigFile(configFile, logger)

	config, err := LoadConfig(configFile, clock)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	warnUnreadableSSHKeys(config, logger)

	// Initialize dependencies
	healthChecker := NewEndpointHealthChecker(logger, clock)
	wolSender := NewUDPWOLSender(logger)
	sshExecutor := NewDefaultSSHExecutor(logger)

	var cache *CacheStore
	if config.CacheEnabled {
		cache = NewCacheStore(config.CacheRootPath, config.CacheTTL, config.CacheMaxResponseSize, config.CacheRoutes, logger)
	}

	// Create proxy service
	proxy := NewProxyService(config, healthChecker, wolSender, sshExecutor, logger, clock, cache)

	// Start the service, shutting down cleanly on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	logger.Info("Shut down cleanly")
}
