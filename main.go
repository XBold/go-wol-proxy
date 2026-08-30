package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// Log levels
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

func ParseLogLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "dbg":
		return LogLevelDebug
	case "warn", "warning":
		return LogLevelWarn
	case "error", "err":
		return LogLevelError
	case "info", "inf", "":
		return LogLevelInfo
	default:
		return LogLevelInfo
	}
}

func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "debug"
	case LogLevelInfo:
		return "info"
	case LogLevelWarn:
		return "warn"
	case LogLevelError:
		return "error"
	default:
		return "info"
	}
}

// Interfaces for dependency injection
type HealthChecker interface {
	Check(ctx context.Context, endpoint string, source string) bool
	StartBackgroundChecks(ctx context.Context, targets map[string]*TargetState, interval time.Duration)
	WaitForInitialChecks(ctx context.Context) error
	CloseIdleConnections()
}

type WOLSender interface {
	SendWOL(macAddr, broadcastIP string, port int) error
}

type SSHExecutor interface {
	ExecuteCommand(host, user, keyPath, knownHosts, command string) error
}

type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// Config structs
type Config struct {
	Port                  string      `toml:"port"`
	Timeout               string      `toml:"timeout"`
	StartupTime           string      `toml:"startup_time"`
	ResponseHeaderTimeout string      `toml:"response_header_timeout"`
	ResponseTimeout       string      `toml:"response_timeout"`
	RequestTimeout        string      `toml:"request_timeout"`
	HealthCheckInterval   string      `toml:"health_check_interval"`
	HealthCacheDuration   string      `toml:"health_cache_duration"`
	SSLCertificate        string      `toml:"ssl_certificate"`
	SSLCertificateKey     string      `toml:"ssl_certificate_key"`
	LogLevel              string      `toml:"log_level"`
	Targets               []Target    `toml:"targets"`
	CacheConfig           CacheConfig `toml:"cache"`
}

type Target struct {
	Name                    string `toml:"name"`
	Hostname                string `toml:"hostname"`
	Destination             string `toml:"destination"`
	HealthEndpoint          string `toml:"health_endpoint"`
	MacAddress              string `toml:"mac_address"`
	BroadcastIP             string `toml:"broadcast_ip"`
	WolPort                 int    `toml:"wol_port"`
	WOLBurstCount           int    `toml:"wol_burst_count"`
	WakeTimeout             string `toml:"wake_timeout"`
	WakeHealthCheckInterval string `toml:"wake_health_check_interval"`
	SSHHost                 string `toml:"ssh_host"`
	SSHUser                 string `toml:"ssh_user"`
	SSHKeyPath              string `toml:"ssh_key_path"`
	SSHKnownHosts           string `toml:"ssh_known_hosts"`
	ShutdownCommand         string `toml:"shutdown_command"`
	ShutdownHTTPUrl         string `toml:"shutdown_http_url"`
	ShutdownHTTPMethod      string `toml:"shutdown_http_method"`
	ShutdownHTTPOKStatus    int    `toml:"shutdown_http_ok_status"`
	InactivityThreshold     string `toml:"inactivity_threshold"`
}

type CacheConfig struct {
	Enabled              bool                `toml:"enabled"`
	RootPath             string              `toml:"root_path"`
	TTL                  string              `toml:"ttl"`
	MaxResponseSizeBytes int64               `toml:"max_response_size_bytes"`
	WarmInterval         string              `toml:"warm_interval"`
	Targets              []CacheTargetConfig `toml:"targets"`
}

type CacheTargetConfig struct {
	Target string   `toml:"target"`
	Paths  []string `toml:"paths"`
}

type ProxyConfig struct {
	Port                  string
	Timeout               time.Duration
	StartupTime           time.Duration
	ResponseHeaderTimeout time.Duration
	ResponseTimeout       time.Duration
	RequestTimeout        time.Duration
	HealthCheckInterval   time.Duration
	HealthCacheDuration   time.Duration
	LogLevel              string
	Targets               map[string]*TargetState
	HostnameMap           map[string]string        // hostname -> target name
	InactivityThresholds  map[string]time.Duration // target name -> inactivity threshold
	WakeTimeouts          map[string]time.Duration // target name -> wake timeout (unset -> global Timeout)
	WakeCheckIntervals    map[string]time.Duration // target name -> fixed health check interval during wake (unset -> adaptive)
	SSLCertificate        string
	SSLCertificateKey     string
	CacheEnabled          bool
	CacheRootPath         string
	CacheTTL              time.Duration
	CacheMaxResponseSize  int64
	CacheWarmInterval     time.Duration
	CachePaths            map[string][]string // target name -> list of cached paths
}

type TargetState struct {
	Target       *Target
	IsHealthy    bool
	LastCheck    time.Time
	IsWaking     bool
	wakeGen      int       // monotonically increasing generation counter for wake operations
	wake         *wakeInfo // in-flight (or most recently completed) wake generation
	LastActivity time.Time
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

type cacheEntry struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"-"`
	Timestamp  time.Time           `json:"timestamp"`
	Path       string              `json:"path"`
}

type CacheStore struct {
	rootPath    string
	ttl         time.Duration
	maxSize     int64
	logger      Logger
	entriesMu   sync.RWMutex
	entries     map[string]*cacheEntry
	targetPaths map[string][]string // target name -> list of patterns
	keyToTarget map[string]string   // cache key -> target name
	keyToPath   map[string]string   // cache key -> path
	accessOrder []string
	maxEntries  int
	lastHashes  map[string][]byte // cache key -> last SHA-256 hash of body
}

func NewCacheStore(rootPath string, ttl time.Duration, maxSize int64, targetPaths map[string][]string, logger Logger) *CacheStore {
	cs := &CacheStore{
		rootPath:    rootPath,
		ttl:         ttl,
		maxSize:     maxSize,
		logger:      logger,
		entries:     make(map[string]*cacheEntry),
		targetPaths: targetPaths,
		keyToTarget: make(map[string]string),
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

func (cs *CacheStore) key(targetName, path string) string {
	hash := sha256.Sum256([]byte(targetName + path))
	return fmt.Sprintf("%x", hash[:16])
}

func (cs *CacheStore) cacheFilePath(targetName, path string) string {
	return filepath.Join(cs.rootPath, targetName, cs.key(targetName, path)+".cache")
}

func (cs *CacheStore) load(targetName, path string) (*cacheEntry, bool) {
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return nil, false
	}

	cacheFile := cs.cacheFilePath(targetName, path)

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, false
	}

	var entry cacheEntry
	if meta, body, ok := parseCacheEnvelope(data); ok && meta.Path == path {
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
	k := cs.key(targetName, path)
	if _, exists := cs.entries[k]; !exists {
		cs.entries[k] = &entry
		cs.keyToTarget[k] = targetName
		cs.keyToPath[k] = path
		cs.addToAccessOrder(k)
	}
	cs.entriesMu.Unlock()

	return &entry, true
}

func (cs *CacheStore) Save(targetName, path string, statusCode int, headers http.Header, body []byte) {
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return
	}

	if int64(len(body)) > cs.maxSize {
		cs.logger.Error("Response too large for cache (%d bytes) for %s %s", len(body), targetName, path)
		return
	}

	bodyHash := sha256.Sum256(body)
	cacheFile := cs.cacheFilePath(targetName, path)

	cs.entriesMu.Lock()
	k := cs.key(targetName, path)
	if lastHash, exists := cs.lastHashes[k]; exists && bytes.Equal(lastHash, bodyHash[:]) {
		// Unchanged content only allows skipping the write while the cache
		// file is still on disk: the file can disappear independently of
		// lastHashes (TTL expiry in load, manual cleanup, ...). Skipping the
		// write in that case would leave the cache empty forever for
		// unchanged responses (e.g. a static model list), sending WOL on
		// every offline request.
		if _, err := os.Stat(cacheFile); err == nil {
			cs.entriesMu.Unlock()
			cs.logger.Debug("Cache unchanged for %s %s, skipping write", targetName, path)
			return
		}
	}
	cs.entriesMu.Unlock()

	cacheDir := filepath.Join(cs.rootPath, targetName)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		cs.logger.Error("Failed to create cache directory %s: %v", cacheDir, err)
		return
	}

	meta := &cacheEntry{
		StatusCode: statusCode,
		Headers:    sanitizeCachedHeaders(headers),
		Body:       body,
		Timestamp:  time.Now(),
		Path:       path,
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
	cs.keyToTarget[k] = targetName
	cs.keyToPath[k] = path
	cs.addToAccessOrder(k)
	cs.lastHashes[k] = bodyHash[:]
	cs.entriesMu.Unlock()

	cs.logger.Info("Cache updated for %s %s", targetName, path)
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
func writeFileAtomic(path string, data []byte) error {
	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpFile, path); err != nil {
		os.Remove(tmpFile)
		return err
	}
	return nil
}

func (cs *CacheStore) Get(targetName, path string) (*http.Response, bool) {
	entry, ok := cs.load(targetName, path)
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

func (cs *CacheStore) GetCachedPathsForTarget(targetName string) []string {
	cs.entriesMu.RLock()
	defer cs.entriesMu.RUnlock()

	targetPaths, exists := cs.targetPaths[targetName]
	if !exists || len(targetPaths) == 0 {
		return nil
	}

	var result []string
	for _, pattern := range targetPaths {
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			for key := range cs.keyToPath {
				if cs.keyToTarget[key] == targetName {
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

func (cs *CacheStore) InvalidateTarget(targetName string) {
	cs.entriesMu.Lock()
	defer cs.entriesMu.Unlock()

	keysToRemove := []string{}
	for k, t := range cs.keyToTarget {
		if t == targetName {
			keysToRemove = append(keysToRemove, k)
		}
	}

	for _, k := range keysToRemove {
		delete(cs.entries, k)
		delete(cs.keyToTarget, k)
		delete(cs.keyToPath, k)
		delete(cs.lastHashes, k)
	}

	cacheDir := filepath.Join(cs.rootPath, targetName)
	if err := os.RemoveAll(cacheDir); err != nil {
		cs.logger.Error("Failed to remove cache directory %s: %v", cacheDir, err)
	}

	cs.logger.Info("Cache invalidated for target: %s (removed %d entries)", targetName, len(keysToRemove))
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
		delete(cs.keyToTarget, oldest)
		delete(cs.keyToPath, oldest)
	}
}

func (cs *CacheStore) loadAll() {
	targets := make(map[string]bool)
	for targetName := range cs.targetPaths {
		targets[targetName] = true
	}

	for targetName := range targets {
		dir := filepath.Join(cs.rootPath, targetName)
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
			cs.keyToTarget[k] = targetName
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
		targetName := cs.keyToTarget[k]
		path := cs.keyToPath[k]

		delete(cs.entries, k)
		delete(cs.keyToTarget, k)
		delete(cs.keyToPath, k)
		delete(cs.lastHashes, k)

		// Also remove the expired files from disk, not just the in-memory bookkeeping.
		if targetName != "" && path != "" {
			cacheFile := cs.cacheFilePath(targetName, path)
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

// HTTP Health Checker implementation
type HTTPHealthChecker struct {
	client           *http.Client
	logger           Logger
	initialCheckDone map[string]bool
	initialCheckMu   sync.RWMutex
	initialWaitGroup sync.WaitGroup
}

func NewHTTPHealthChecker(logger Logger) *HTTPHealthChecker {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	return &HTTPHealthChecker{
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		},
		logger:           logger,
		initialCheckDone: make(map[string]bool),
	}
}

func (h *HTTPHealthChecker) CloseIdleConnections() {
	if transport, ok := h.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (h *HTTPHealthChecker) Check(ctx context.Context, endpoint string, source string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		h.logger.Debug("Health check (%s) failed for %s: %v", source, endpoint, err)
		return false
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Debug("Health check (%s) failed for %s: %v", source, endpoint, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.logger.Debug("Health check (%s) failed for %s: status %d", source, endpoint, resp.StatusCode)
		return false
	}

	return true
}

func (h *HTTPHealthChecker) StartBackgroundChecks(ctx context.Context, targets map[string]*TargetState, interval time.Duration) {
	for name, target := range targets {
		h.initialWaitGroup.Add(1)
		go h.backgroundCheck(ctx, name, target, interval)
	}
}

func (h *HTTPHealthChecker) WaitForInitialChecks(ctx context.Context) error {
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

func (h *HTTPHealthChecker) backgroundCheck(ctx context.Context, name string, target *TargetState, interval time.Duration) {
	// Perform initial check
	h.performCheck(name, target)
	h.markInitialCheckDone(name)
	h.initialWaitGroup.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.performCheck(name, target)
		}
	}
}

func (h *HTTPHealthChecker) performCheck(name string, target *TargetState) {
	target.mu.RLock()
	isWaking := target.IsWaking
	target.mu.RUnlock()
	if isWaking {
		h.logger.Debug("Background health check for %s (%s) running while wake is in progress",
			name, target.Target.Hostname)
	}

	checkStarted := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthy := h.Check(ctx, target.Target.HealthEndpoint, "background")

	target.mu.Lock()
	previousHealth := target.IsHealthy
	target.IsHealthy = healthy
	target.LastCheck = time.Now()
	target.mu.Unlock()

	if healthy != previousHealth {
		status := "DOWN"
		if healthy {
			status = "UP"
		}
		h.logger.Info("Health check for %s (%s): %s", name, target.Target.Hostname, status)
	}

	if !healthy && previousHealth {
		h.logger.Info(
			"Background health check for %s (%s): downgrading healthy to unhealthy (check took %v)",
			name, target.Target.Hostname, time.Since(checkStarted).Round(time.Millisecond),
		)
	}

	if !healthy {
		h.CloseIdleConnections()
	}
}

func (h *HTTPHealthChecker) markInitialCheckDone(name string) {
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

func (s *DefaultSSHExecutor) ExecuteCommand(host, user, keyPath, knownHosts, command string) error {
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

	// Configure host key callback
	var hostKeyCallback ssh.HostKeyCallback
	if knownHosts != "" {
		hostKeyCallback, err = newKnownHostsCallback(knownHosts)
		if err != nil {
			return fmt.Errorf("failed to create known_hosts callback: %w", err)
		}
	} else {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
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

func newKnownHostsCallback(filename string) (ssh.HostKeyCallback, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read known_hosts file %s: %w", filename, err)
	}

	knownHosts := make(map[string]ssh.PublicKey)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, hosts, pubKey, _, _, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil || pubKey == nil {
			continue
		}
		for _, host := range hosts {
			knownHosts[host] = pubKey
		}
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Try exact hostname match first
		if storedKey, ok := knownHosts[hostname]; ok {
			if bytes.Equal(storedKey.Marshal(), key.Marshal()) {
				return nil
			}
			return fmt.Errorf("host key mismatch for %s", hostname)
		}
		// Try wildcard pattern matching (e.g., *.example.com)
		for pattern, storedKey := range knownHosts {
			if matched, _ := filepath.Match(pattern, hostname); matched {
				if bytes.Equal(storedKey.Marshal(), key.Marshal()) {
					return nil
				}
				return fmt.Errorf("host key mismatch for %s (matched pattern %s)", hostname, pattern)
			}
		}
		return fmt.Errorf("no known host key found for %s", hostname)
	}, nil
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

	w.logger.Debug("WOL packet sent to %s via %s:%d", macAddr, broadcastIP, port)
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
	logger         Logger
	cache          *CacheStore
	proxyTransport *http.Transport
}

func NewProxyService(
	config *ProxyConfig,
	healthChecker HealthChecker,
	wolSender WOLSender,
	sshExecutor SSHExecutor,
	logger Logger,
	cache *CacheStore,
) *ProxyService {
	// A single shared transport is reused across all proxied requests (for all
	// targets - Go's Transport already pools connections per scheme+host, so one
	// instance is enough). Creating a fresh *http.Transport per request would mean
	// no keep-alive connection reuse and, since http.Transport has no finalizer
	// that closes idle connections when garbage collected, a slow leak of open
	// sockets under sustained traffic.
	proxyTransport := &http.Transport{
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
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		// No timeout for reading the entire response
		ReadBufferSize:  1024 * 1024, // 1MB buffer for reading
		WriteBufferSize: 1024 * 1024, // 1MB buffer for writing
	}

	return &ProxyService{
		config:         config,
		healthChecker:  healthChecker,
		wolSender:      wolSender,
		sshExecutor:    sshExecutor,
		logger:         logger,
		cache:          cache,
		proxyTransport: proxyTransport,
	}
}

func (p *ProxyService) shutdownTarget(targetName string) error {
	targetState, exists := p.config.Targets[targetName]
	if !exists {
		return fmt.Errorf("unknown target: %s", targetName)
	}

	target := targetState.Target
	if (target.SSHHost == "" || target.SSHUser == "" || target.SSHKeyPath == "" || target.ShutdownCommand == "") && target.ShutdownHTTPUrl == "" {
		return fmt.Errorf("target %s is missing SSH configuration or shutdown command or shutdown HTTP URL", targetName)
	}

	p.logger.Info("Shutting down target %s (%s) due to inactivity", targetName, target.Hostname)
	if target.ShutdownHTTPUrl != "" {
		// Attempt to shut down via HTTP request
		method := target.ShutdownHTTPMethod
		if method == "" {
			method = "POST" // Default to POST if not specified
		}

		req, err := http.NewRequest(method, target.ShutdownHTTPUrl, nil)
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
		if target.ShutdownHTTPOKStatus != 0 {
			if resp.StatusCode != target.ShutdownHTTPOKStatus {
				return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
			}
		} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
		}

	} else {
		err := p.sshExecutor.ExecuteCommand(target.SSHHost, target.SSHUser, target.SSHKeyPath, target.SSHKnownHosts, target.ShutdownCommand)
		if err != nil {
			p.logger.Error("Failed to shut down target %s: %v", targetName, err)
			return err
		}
	}

	// Mark the target as unhealthy after shutdown
	targetState.mu.Lock()
	targetState.IsHealthy = false
	targetState.mu.Unlock()
	p.healthChecker.CloseIdleConnections()
	p.proxyTransport.CloseIdleConnections()

	p.logger.Info("Target %s (%s) has been shut down", targetName, target.Hostname)
	return nil
}

func (p *ProxyService) startInactivityMonitor(ctx context.Context) {
	// Check every 10 seconds for inactive targets
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkInactiveTargets()
		}
	}
}

func (p *ProxyService) checkInactiveTargets() {
	now := time.Now()

	for name, targetState := range p.config.Targets {
		// Skip targets without inactivity threshold
		threshold, exists := p.config.InactivityThresholds[name]
		if !exists {
			continue
		}

		// Skip targets that are not healthy (already down)
		targetState.mu.RLock()
		isHealthy := targetState.IsHealthy
		lastActivity := targetState.LastActivity
		targetState.mu.RUnlock()

		if !isHealthy {
			continue
		}

		// Check if the target has been inactive for too long
		inactiveDuration := now.Sub(lastActivity)
		if inactiveDuration > threshold {
			p.logger.Info("Target %s has been inactive for %v (threshold: %v), shutting down",
				name, inactiveDuration.Round(time.Second), threshold)

			if err := p.shutdownTarget(name); err != nil {
				p.logger.Error("Failed to shut down inactive target %s: %v", name, err)
			}
		}
	}
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

	for _, targetState := range p.config.Targets {
		targetState.mu.RLock()
		isHealthy := targetState.IsHealthy
		targetState.mu.RUnlock()
		if isHealthy {
			p.warmCache(targetState.Target.Name)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, targetState := range p.config.Targets {
				targetState.mu.RLock()
				isHealthy := targetState.IsHealthy
				targetState.mu.RUnlock()

				if isHealthy {
					p.warmCache(targetState.Target.Name)
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
		p.config.Targets,
		p.config.HealthCheckInterval,
	)

	// Wait for initial health checks to complete
	p.logger.Info("Waiting for initial health checks to complete...")
	if err := p.healthChecker.WaitForInitialChecks(ctx); err != nil {
		return fmt.Errorf("initial health checks failed: %w", err)
	}

	// Start background inactivity monitor
	go p.startInactivityMonitor(ctx)

	// Start cache background tasks if cache is enabled
	if p.cache != nil && p.config.CacheEnabled {
		p.logger.Info("Cache enabled, root path: %s, TTL: %v, warm interval: %v",
			p.config.CacheRootPath, p.config.CacheTTL, p.config.CacheWarmInterval)

		go p.startCacheCleanup(ctx)
		go p.startCacheWarming(ctx)
	}

	p.logger.Info("Initial health checks completed, starting HTTP server")

	// Log configured targets
	for name, target := range p.config.Targets {
		p.logger.Info("Configured target: %s -> %s (%s)",
			target.Target.Hostname, name, target.Target.Destination)
	}

	// Start HTTP/HTTPS server
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	server := &http.Server{
		Addr:              p.config.Port,
		Handler:           mux,
		ReadTimeout:       p.config.RequestTimeout,
		WriteTimeout:      p.config.ResponseTimeout,
		IdleTimeout:       120 * time.Second, // 2 minutes for keep-alive connections
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

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

		p.logger.Info("HTTPS server listening on %s with SSL certificates", p.config.Port)
		return p.serveAndWaitForShutdown(ctx, server, func() error {
			//The files in these methods are ignored since there is already a certificate in the config.
			return server.ListenAndServeTLS("", "")
		})
	} else {
		p.logger.Info("HTTP server listening on %s", p.config.Port)
		return p.serveAndWaitForShutdown(ctx, server, server.ListenAndServe)
	}
}

// serveAndWaitForShutdown runs the HTTP(S) server in the background and blocks until
// either the server stops on its own (returning its error, if any) or ctx is
// cancelled (e.g. via SIGINT/SIGTERM), in which case the server is shut down
// gracefully with a bounded timeout.
func (p *ProxyService) serveAndWaitForShutdown(ctx context.Context, server *http.Server, serve func() error) error {
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serve()
	}()

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-ctx.Done():
		p.logger.Info("Shutdown signal received, stopping server gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			p.logger.Error("Error during server shutdown: %v", err)
			return err
		}

		if p.cache != nil {
			p.cache.Close()
		}
		p.proxyTransport.CloseIdleConnections()
		p.healthChecker.CloseIdleConnections()

		p.logger.Info("Server stopped gracefully")
		return nil
	}
}

func (p *ProxyService) handleRequest(w http.ResponseWriter, r *http.Request) {
	targetName := p.extractTarget(r)

	if targetName == "" {
		p.logger.Error("No target found for hostname: %s", r.Host)
		http.Error(w, "No target configured for this hostname", http.StatusNotFound)
		return
	}

	p.logger.Info("Incoming request for hostname: %s -> target: %s, path: %s (client: %s)",
		r.Host, targetName, r.URL.Path, r.RemoteAddr)

	targetState, exists := p.config.Targets[targetName]
	if !exists {
		p.logger.Error("Unknown target: %s", targetName)
		http.Error(w, "Target not found", http.StatusNotFound)
		return
	}

	// Check if we have fresh health data
	cached, reason := p.healthCacheStatus(r.Context(), targetName, targetState)
	if cached {
		p.logger.Info("Target %s is healthy, proxying immediately", targetName)
		p.proxyRequest(w, r, targetState.Target)
		return
	}

	// Check static cache before triggering WOL
	if p.cache != nil && p.config.CacheEnabled {
		if r.Method == "GET" {
			if resp, ok := p.cache.Get(targetName, r.URL.Path); ok {
				p.logger.Info("Serving cached response for %s %s (target %s is down)",
					r.Method, r.URL.Path, targetName)
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
	}

	// Need to wake up the server
	p.logger.Info("Target %s appears down (%s), attempting to wake", targetName, reason)
	p.healthChecker.CloseIdleConnections()
	if _, err := p.wakeAndWait(r.Context(), targetState); err != nil {
		if r.Context().Err() != nil {
			// The client went away while the wake was pending. The wake itself
			// runs independently of this request (see wakeAndWait), so the
			// target will still be confirmed (and the cache refreshed) in the
			// background; only this client gets no response.
			p.logger.Info("Client %s disconnected while waiting for %s to wake (%v)",
				r.RemoteAddr, targetName, err)
			return
		}
		p.logger.Error("Failed to wake target %s: %v", targetName, err)
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := r.Context().Err(); err != nil {
		// The wake completed in the background but the client no longer wants
		// the response. The next request will hit the now-healthy target.
		p.logger.Info("Client %s disconnected while %s was waking; aborting request",
			r.RemoteAddr, targetName)
		return
	}

	p.logger.Info("Target %s is now healthy, proxying request", targetName)
	p.proxyRequest(w, r, targetState.Target)
}

func (p *ProxyService) extractTarget(r *http.Request) string {
	// Remove port from host if present
	host := r.Host
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Look up target by hostname
	if targetName, exists := p.config.HostnameMap[host]; exists {
		return targetName
	}

	return ""
}

// healthCacheStatus reports whether the target can be treated as healthy
// right now. If the last background check marked it healthy but that check
// has aged past health_cache_duration, we don't immediately assume it's
// down - background checks only run every health_check_interval, so if
// health_check_interval > health_cache_duration there would otherwise be a
// recurring window (between the two durations) where a perfectly healthy
// target is wrongly treated as down and a WOL burst is fired for no reason.
// Instead we perform a quick synchronous re-check here before giving up.
func (p *ProxyService) healthCacheStatus(ctx context.Context, targetName string, target *TargetState) (cached bool, reason string) {
	target.mu.RLock()
	wasHealthy := target.IsHealthy
	lastCheck := target.LastCheck
	target.mu.RUnlock()

	if !wasHealthy {
		if lastCheck.IsZero() {
			return false, "no prior health check"
		}
		return false, fmt.Sprintf(
			"marked unhealthy (last check %v ago)",
			time.Since(lastCheck).Round(time.Second),
		)
	}

	age := time.Since(lastCheck)
	if age <= p.config.HealthCacheDuration {
		return true, ""
	}

	// Cached health is stale but the target was healthy as of the last
	// check. Do an on-demand check (short timeout) instead of assuming down.
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	healthy := p.healthChecker.Check(checkCtx, target.Target.HealthEndpoint, "on-demand")

	target.mu.Lock()
	target.IsHealthy = healthy
	target.LastCheck = time.Now()
	target.mu.Unlock()

	if healthy {
		p.logger.Debug("On-demand health re-check for %s succeeded (stale cache: last check %v ago)",
			targetName, age.Round(time.Second))
		return true, ""
	}

	p.logger.Info("On-demand health re-check for %s failed (last background check %v ago)",
		targetName, age.Round(time.Second))
	return false, fmt.Sprintf(
		"on-demand health check failed (last background check %v ago, cache duration %v)",
		age.Round(time.Second), p.config.HealthCacheDuration,
	)
}

// wakeAndWait makes sure a wake is in flight for the target, then makes the
// caller wait for its outcome bounded by the caller's ctx. The wake itself is
// owned by the proxy, not by any request: it runs in its own goroutine on a
// background context (see runWake), so it keeps going even if the client that
// triggered it - or every client - times out, disconnects, or the proxy is
// asked to shut down. All requests (the one that started the wake and any
// that join it) merely wait on the shared completion channel of the same
// wake generation; a client that leaves only stops waiting, it never cancels
// the wake.
func (p *ProxyService) wakeAndWait(ctx context.Context, target *TargetState) (int, error) {
	var gen int
	var info *wakeInfo
	target.mu.Lock()
	if !target.IsWaking {
		target.wakeGen++
		gen = target.wakeGen
		target.IsWaking = true
		target.LastActivity = time.Now()
		info = &wakeInfo{gen: gen, done: make(chan struct{})}
		target.wake = info
		target.mu.Unlock()

		p.logger.Info("Target %s (%s) is down, starting wake (gen=%d)",
			target.Target.Name, target.Target.Hostname, gen)
		go p.runWake(target, info)
	} else {
		gen = target.wakeGen
		info = target.wake
		target.mu.Unlock()
		p.logger.Info("Target %s (%s) wake already in progress, joining existing wait (gen=%d)",
			target.Target.Name, target.Target.Hostname, gen)
	}
	return gen, p.joinWake(ctx, target, info)
}

// runWake performs the actual wake (WOL packet + health polling) for one
// generation, fully detached from any request context. Clients routinely time
// out (e.g. 10s) long before a machine can boot (startup_time defaults to
// 30s), so the wake must outlive them: it runs on a fresh background context
// bounded only by the (per-target) wake timeout, and it always reaches
// finishWake, which releases every waiter and clears IsWaking.
func (p *ProxyService) runWake(target *TargetState, info *wakeInfo) {
	if err := p.wolSender.SendWOL(
		target.Target.MacAddress,
		target.Target.BroadcastIP,
		target.Target.WolPort,
	); err != nil {
		p.finishWake(target, info, fmt.Errorf("failed to send WOL: %w", err))
		return
	}

	p.logger.Info("WOL packet sent to %s (%s), waiting for server to wake (gen=%d)",
		target.Target.Name, target.Target.Hostname, info.gen)

	wakeCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.finishWake(target, info, p.waitForWake(wakeCtx, target, info.gen))
}

// finishWake publishes the outcome of a wake generation, clears IsWaking and
// releases every waiter in one critical section, so no new wake generation
// can start in between the state update and the close of done: joiners that
// wake up on done always observe the result of the generation they joined.
func (p *ProxyService) finishWake(target *TargetState, info *wakeInfo, err error) {
	target.mu.Lock()
	if target.wakeGen == info.gen {
		target.IsWaking = false
	}
	info.err = err
	target.mu.Unlock()
	close(info.done)
}

// joinWake makes a request wait for one wake generation to finish, bounded by
// the request's ctx. A result of ctx.Err() only means "this client stopped
// waiting"; the wake itself keeps running (runWake is detached from the
// request), so the target is still confirmed - and the post-wake cache
// refresh still runs - even if every client gave up.
func (p *ProxyService) joinWake(ctx context.Context, target *TargetState, info *wakeInfo) error {
	if info == nil {
		return fmt.Errorf("no in-flight wake to join for %s", target.Target.Name)
	}

	select {
	case <-info.done:
		// finishWake published info.err in the same critical section that
		// cleared IsWaking, before closing done: it always describes this
		// generation, even if a new wake has already started meanwhile.
		target.mu.RLock()
		healthy := target.IsHealthy
		target.mu.RUnlock()
		if healthy {
			return nil
		}
		if info.err != nil {
			return info.err
		}
		return fmt.Errorf("wake failed for %s", target.Target.Name)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitForWake repeatedly sends a burst of WOL packets and waits for the
// target to come up. Each cycle is strictly: send a burst of burstCount
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
//   - fixed: the target's wake_health_check_interval (e.g. 2s), which spots
//     a booted machine within one interval (also floored at 500ms).
//
// The whole operation is bounded by the target's wake timeout (its
// wake_timeout, or the global timeout when the target does not override it)
// - deliberately independent of any client request's deadline.
func (p *ProxyService) waitForWake(ctx context.Context, target *TargetState, wakeGen int) error {
	wakeTimeout := p.config.Timeout
	if perTarget, ok := p.config.WakeTimeouts[target.Target.Name]; ok {
		wakeTimeout = perTarget
	}
	checkInterval := p.config.WakeCheckIntervals[target.Target.Name]

	timeout := time.After(wakeTimeout)
	wakeStartTime := time.Now()
	waitDuration := p.config.StartupTime
	burstCount := 3
	if target.Target.WOLBurstCount > 0 {
		if target.Target.WOLBurstCount < 1 {
			burstCount = 1
		} else if target.Target.WOLBurstCount > 10 {
			burstCount = 10
		} else {
			burstCount = target.Target.WOLBurstCount
		}
	}
	burstInterval := 500 * time.Millisecond

	// sendWOLBurst sends burstCount WOL packets burstInterval apart. It
	// returns early (with ctx.Err()) if the context is cancelled mid-burst.
	sendWOLBurst := func() error {
		for i := 0; i < burstCount; i++ {
			if err := p.wolSender.SendWOL(
				target.Target.MacAddress,
				target.Target.BroadcastIP,
				target.Target.WolPort,
			); err != nil {
				p.logger.Error("Failed to send WOL packet during burst: %v", err)
			} else {
				p.logger.Info("Sent WOL burst packet %d/%d to %s (%s)",
					i+1, burstCount, target.Target.Name, target.Target.Hostname)
			}
			if i < burstCount-1 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timeout:
					return fmt.Errorf("timeout waiting for %s to wake up after %v",
						target.Target.Name, wakeTimeout)
				case <-time.After(burstInterval):
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
				target.Target.Name, wakeTimeout)
		case <-time.After(waitDuration):
		}

		if p.healthChecker.Check(ctx, target.Target.HealthEndpoint, "wake") {
			target.mu.Lock()
			target.IsHealthy = true
			target.LastCheck = time.Now()
			target.mu.Unlock()

			wakeDuration := time.Since(wakeStartTime)
			p.logger.Info("Target %s (%s) woke up after %v (gen=%d)",
				target.Target.Name, target.Target.Hostname, wakeDuration, wakeGen)

			if p.cache != nil && p.config.CacheEnabled {
				// Refresh the cached paths now that the target is reachable
				// again. This used to only *invalidate* the cache and rely on
				// the next warm tick (up to warm_interval later) or a future
				// proxied GET to repopulate it: if the target went offline
				// before that happened, cached endpoints (e.g. /models) fell
				// back to triggering WOL on every request. Refreshing in place
				// (instead of deleting first) also keeps the previous entries
				// servable if the refresh itself fails.
				go p.warmCache(target.Target.Name)
			}

			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for %s to wake up after %v",
				target.Target.Name, wakeTimeout)
		default:
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
}

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

func (p *ProxyService) warmCache(targetName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	p.logger.Debug("Starting cache warmup for target: %s", targetName)

	cachedPaths := p.cache.GetCachedPathsForTarget(targetName)
	if len(cachedPaths) == 0 {
		p.logger.Debug("No cached paths to warm for target: %s", targetName)
		return
	}

	targetState, exists := p.config.Targets[targetName]
	if !exists {
		return
	}

	target := targetState.Target
	targetURL, err := url.Parse(target.Destination)
	if err != nil {
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    true,
		},
	}

	for _, path := range cachedPaths {
		select {
		case <-ctx.Done():
			p.logger.Debug("Cache warmup cancelled for target: %s", targetName)
			return
		case <-time.After(100 * time.Millisecond):
		}

		reqURL := *targetURL
		reqURL.Path = path

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
		if err != nil {
			p.logger.Error("Failed to create request for %s %s: %v", targetName, path, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			p.logger.Error("Failed to warm cache for %s %s: %v", targetName, path, err)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, err := io.ReadAll(io.LimitReader(resp.Body, p.config.CacheMaxResponseSize))
			resp.Body.Close()

			if err == nil {
				p.cache.Save(targetName, path, resp.StatusCode, resp.Header, body)
			}
		} else {
			resp.Body.Close()
		}
	}

	p.logger.Debug("Cache warmup completed for target: %s", targetName)
}

func (p *ProxyService) proxyRequest(w http.ResponseWriter, r *http.Request, target *Target) {
	if targetState, exists := p.config.Targets[target.Name]; exists {
		targetState.mu.Lock()
		targetState.LastActivity = time.Now()
		targetState.mu.Unlock()
	}

	targetURL, err := url.Parse(target.Destination)
	if err != nil {
		p.logger.Error("Invalid target URL %s: %v", target.Destination, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = p.proxyTransport

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
		p.logger.Error("Proxy error for %s (%s): %v", target.Name, target.Hostname, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}

	// Disable buffering of response body for streaming uploads/downloads
	proxy.ModifyResponse = func(resp *http.Response) error {
		p.logger.Info("Response from %s: status=%d, content-length=%d",
			target.Name, resp.StatusCode, resp.ContentLength)

		if p.cache != nil && p.config.CacheEnabled && r.Method == "GET" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			cachePaths, exists := p.config.CachePaths[target.Name]
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
								p.cache.Save(target.Name, r.URL.Path, resp.StatusCode, resp.Header, body)
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
func LoadConfig(filename string) (*ProxyConfig, error) {
	var config Config
	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return nil, err
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

	// timeout is the default wake timeout: how long to wait for a target to
	// boot after a WOL packet. It is optional (defaults to 2m) and can be
	// overridden per target with wake_timeout.
	timeout := 120 * time.Second
	if config.Timeout != "" {
		timeout, err = time.ParseDuration(config.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
	}

	startupTime := 30 * time.Second
	if config.StartupTime != "" {
		startupTime, err = time.ParseDuration(config.StartupTime)
		if err != nil {
			return nil, fmt.Errorf("invalid startup_time: %w", err)
		}
	}
	if startupTime >= timeout {
		return nil, fmt.Errorf("startup_time (%v) must be less than timeout (%v)", startupTime, timeout)
	}

	if config.ResponseHeaderTimeout == "" {
		config.ResponseHeaderTimeout = "1m"
	}
	responseHeaderTimeout, err := time.ParseDuration(config.ResponseHeaderTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid response_header_timeout: %w", err)
	}

	// Parse response_timeout: 0 means no timeout (useful for SSE/long streams)
	responseTimeout := time.Duration(0)
	if config.ResponseTimeout != "" {
		responseTimeout, err = time.ParseDuration(config.ResponseTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid response_timeout: %w", err)
		}
	}

	// Parse request_timeout: 0 means no timeout (useful for SSE/long streams)
	requestTimeout := time.Duration(0)
	if config.RequestTimeout != "" {
		requestTimeout, err = time.ParseDuration(config.RequestTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid request_timeout: %w", err)
		}
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
	cachePaths := make(map[string][]string)

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

		for _, ct := range config.CacheConfig.Targets {
			if ct.Target != "" && len(ct.Paths) > 0 {
				cachePaths[ct.Target] = ct.Paths
			}
		}
	}

	targets := make(map[string]*TargetState)
	hostnameMap := make(map[string]string)
	inactivityThresholds := make(map[string]time.Duration)
	wakeTimeouts := make(map[string]time.Duration)
	wakeCheckIntervals := make(map[string]time.Duration)

	for _, target := range config.Targets {
		if target.Hostname == "" {
			return nil, fmt.Errorf("target %s is missing hostname", target.Name)
		}

		// Check for duplicate hostnames
		if existingTarget, exists := hostnameMap[target.Hostname]; exists {
			return nil, fmt.Errorf("duplicate hostname %s for targets %s and %s",
				target.Hostname, existingTarget, target.Name)
		}

		// Validate WOL configuration
		if target.MacAddress == "" {
			return nil, fmt.Errorf("target %s is missing mac_address", target.Name)
		}
		if target.BroadcastIP == "" {
			return nil, fmt.Errorf("target %s is missing broadcast_ip", target.Name)
		}
		if _, err := net.ParseMAC(target.MacAddress); err != nil {
			return nil, fmt.Errorf("target %s has invalid mac_address %q: %w", target.Name, target.MacAddress, err)
		}
		if _, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", target.BroadcastIP)); err != nil {
			return nil, fmt.Errorf("target %s has invalid broadcast_ip %q: %w", target.Name, target.BroadcastIP, err)
		}
		if target.WolPort != 0 && (target.WolPort < 1 || target.WolPort > 65535) {
			return nil, fmt.Errorf("target %s has invalid wol_port %d (must be 1-65535 or 0 for default)", target.Name, target.WolPort)
		}
		if target.WolPort == 0 {
			target.WolPort = 9 // standard Wake-on-LAN port
		}

		// Validate shutdown configuration
		// Disallow using both SSH shutdown command and HTTP shutdown URL
		if strings.TrimSpace(target.ShutdownHTTPUrl) != "" && strings.TrimSpace(target.ShutdownCommand) != "" {
			return nil, fmt.Errorf("target %s: cannot define both shutdown_http_url and shutdown_command; choose one", target.Name)
		}

		// Disallow http method/ok status without URL
		if strings.TrimSpace(target.ShutdownHTTPUrl) == "" && (strings.TrimSpace(target.ShutdownHTTPMethod) != "" || target.ShutdownHTTPOKStatus != 0) {
			return nil, fmt.Errorf("target %s: shutdown_http_method and/or shutdown_http_ok_status require shutdown_http_url to be set", target.Name)
		}

		// Parse inactivity threshold if provided
		if target.InactivityThreshold != "" {
			inactivityThreshold, err := time.ParseDuration(target.InactivityThreshold)
			if err != nil {
				return nil, fmt.Errorf("invalid inactivity_threshold for target %s: %w", target.Name, err)
			}
			inactivityThresholds[target.Name] = inactivityThreshold
		}

		// Per-target wake timeout: overrides the global timeout for this
		// target's wake operations only (forwarding is unaffected).
		if target.WakeTimeout != "" {
			wakeTimeout, err := time.ParseDuration(target.WakeTimeout)
			if err != nil {
				return nil, fmt.Errorf("invalid wake_timeout for target %s: %w", target.Name, err)
			}
			if startupTime >= wakeTimeout {
				return nil, fmt.Errorf("startup_time (%v) must be less than wake_timeout (%v) for target %s",
					startupTime, wakeTimeout, target.Name)
			}
			wakeTimeouts[target.Name] = wakeTimeout
		}

		// Per-target health check interval used while the target is waking
		// (after the initial startup_time quiet period). Unset = adaptive
		// halving of startup_time, floored at 500ms.
		if target.WakeHealthCheckInterval != "" {
			wakeCheckInterval, err := time.ParseDuration(target.WakeHealthCheckInterval)
			if err != nil {
				return nil, fmt.Errorf("invalid wake_health_check_interval for target %s: %w", target.Name, err)
			}
			if wakeCheckInterval <= 0 {
				return nil, fmt.Errorf("wake_health_check_interval for target %s must be positive", target.Name)
			}
			wakeCheckIntervals[target.Name] = wakeCheckInterval
		}

		targetCopy := target
		targets[target.Name] = &TargetState{
			Target:       &targetCopy,
			LastActivity: time.Now(), // Initialize with current time
		}
		hostnameMap[target.Hostname] = target.Name
	}

	return &ProxyConfig{
		Port:                  config.Port,
		SSLCertificate:        config.SSLCertificate,
		SSLCertificateKey:     config.SSLCertificateKey,
		Timeout:               timeout,
		StartupTime:           startupTime,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ResponseTimeout:       responseTimeout,
		RequestTimeout:        requestTimeout,
		HealthCheckInterval:   healthCheckInterval,
		HealthCacheDuration:   healthCacheDuration,
		LogLevel:              config.LogLevel,
		Targets:               targets,
		HostnameMap:           hostnameMap,
		InactivityThresholds:  inactivityThresholds,
		WakeTimeouts:          wakeTimeouts,
		WakeCheckIntervals:    wakeCheckIntervals,
		CacheEnabled:          cacheEnabled,
		CacheRootPath:         cacheRootPath,
		CacheTTL:              cacheTTL,
		CacheMaxResponseSize:  cacheMaxResponseSize,
		CacheWarmInterval:     cacheWarmInterval,
		CachePaths:            cachePaths,
	}, nil
}

// Simple logger implementation
type StdLogger struct {
	level    LogLevel
	location *time.Location
}

func (l *StdLogger) shouldLog(level LogLevel) bool {
	return l.level <= level
}

func (l *StdLogger) Info(msg string, args ...interface{}) {
	if l.shouldLog(LogLevelInfo) {
		log.Printf("[INFO] %s "+msg, append([]interface{}{time.Now().In(l.location).Format("2006-01-02 15:04:05")}, args...)...)
	}
}

func (l *StdLogger) Error(msg string, args ...interface{}) {
	if l.shouldLog(LogLevelError) {
		log.Printf("[ERROR] %s "+msg, append([]interface{}{time.Now().In(l.location).Format("2006-01-02 15:04:05")}, args...)...)
	}
}

func (l *StdLogger) Debug(msg string, args ...interface{}) {
	if l.shouldLog(LogLevelDebug) {
		log.Printf("[DEBUG] %s "+msg, append([]interface{}{time.Now().In(l.location).Format("2006-01-02 15:04:05")}, args...)...)
	}
}

// Main function
func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: wol-proxy <config.toml>")
	}

	configFile := os.Args[1]

	// Load configuration
	config, err := LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize dependencies
	tz := os.Getenv("TZ")
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		log.Printf("Invalid timezone %q, defaulting to UTC: %v", tz, err)
		tz = "UTC"
		loc = time.UTC
	}
	logger := &StdLogger{level: ParseLogLevel(config.LogLevel), location: loc}
	healthChecker := NewHTTPHealthChecker(logger)
	wolSender := NewUDPWOLSender(logger)
	sshExecutor := NewDefaultSSHExecutor(logger)

	var cache *CacheStore
	if config.CacheEnabled {
		cache = NewCacheStore(config.CacheRootPath, config.CacheTTL, config.CacheMaxResponseSize, config.CachePaths, logger)
	}

	// Create proxy service
	proxy := NewProxyService(config, healthChecker, wolSender, sshExecutor, logger, cache)

	// Start the service with graceful shutdown on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		select {
		case sig := <-sigChan:
			log.Printf("Received signal %v, initiating graceful shutdown", sig)
		case <-ctx.Done():
			return
		}
		cancel()
	}()

	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
