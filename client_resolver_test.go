package main

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- clientResolver --------------------------------------------------------

func TestClientResolverDisabled(t *testing.T) {
	r := newClientResolver(false)
	r.lookupFn = func(ip string, _ time.Duration) (string, error) {
		t.Fatal("lookup must not run when the resolver is disabled")
		return "", nil
	}
	if _, ok := r.resolve("192.0.2.1"); ok {
		t.Fatal("expected no hostname when the resolver is disabled")
	}
}

func TestClientResolverCachesPositiveResult(t *testing.T) {
	calls := 0
	r := newClientResolver(true)
	r.lookupFn = func(ip string, _ time.Duration) (string, error) {
		calls++
		return "nas.lan.", nil // trailing dot must be stripped
	}

	host, ok := r.resolve("192.0.2.10")
	if !ok || host != "nas.lan" {
		t.Fatalf("got (%q, %v), want (nas.lan, true)", host, ok)
	}
	if _, ok := r.resolve("192.0.2.10"); !ok {
		t.Fatal("cached hostname not returned on second resolve")
	}
	if calls != 1 {
		t.Fatalf("expected 1 lookup, got %d", calls)
	}
}

func TestClientResolverCachesNegativeResult(t *testing.T) {
	calls := 0
	r := newClientResolver(true)
	r.lookupFn = func(ip string, _ time.Duration) (string, error) {
		calls++
		return "", errors.New("no PTR record")
	}

	for i := 0; i < 3; i++ {
		if _, ok := r.resolve("192.0.2.11"); ok {
			t.Fatal("expected no hostname")
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 lookup (negative results are cached), got %d", calls)
	}
}

func TestClientResolverNegativeTTLExpiry(t *testing.T) {
	calls := 0
	r := newClientResolver(true)
	r.negTTL = 15 * time.Millisecond
	r.lookupFn = func(ip string, _ time.Duration) (string, error) {
		calls++
		return "", errors.New("no PTR record")
	}

	r.resolve("192.0.2.12")
	time.Sleep(30 * time.Millisecond)
	r.resolve("192.0.2.12")

	if calls != 2 {
		t.Fatalf("expected the lookup to repeat after the negative TTL, got %d calls", calls)
	}
}

func TestClientResolverDifferentIPsAreIndependent(t *testing.T) {
	seen := map[string]bool{}
	r := newClientResolver(true)
	r.lookupFn = func(ip string, _ time.Duration) (string, error) {
		seen[ip] = true
		return ip + ".example", nil
	}
	if _, ok := r.resolve("192.0.2.20"); !ok {
		t.Fatal("expected hostname for 192.0.2.20")
	}
	if _, ok := r.resolve("192.0.2.21"); !ok {
		t.Fatal("expected hostname for 192.0.2.21")
	}
	if len(seen) != 2 {
		t.Fatalf("expected lookups for both IPs, saw %v", seen)
	}
}

// --- clientAddr --------------------------------------------------------------

func TestClientAddrWithHostname(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.svc.clientResolver = newClientResolver(true)
	tp.svc.clientResolver.lookupFn = func(ip string, _ time.Duration) (string, error) {
		if ip == "172.23.0.3" {
			return "open-webui.", nil
		}
		return "", errors.New("no PTR record")
	}

	req := httptest.NewRequest("GET", "/api/server/ping", nil)
	req.RemoteAddr = "172.23.0.3:57648"

	if got := tp.svc.clientAddr(req); got != "172.23.0.3:57648 (hostname: open-webui)" {
		t.Errorf("clientAddr = %q", got)
	}
}

func TestClientAddrUnresolvableAndForwarded(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.svc.clientResolver = newClientResolver(true)
	tp.svc.clientResolver.lookupFn = func(ip string, _ time.Duration) (string, error) {
		return "", errors.New("no PTR record")
	}

	req := httptest.NewRequest("GET", "/api/server/ping", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	if got := tp.svc.clientAddr(req); got != "203.0.113.7:1234" {
		t.Errorf("clientAddr = %q", got)
	}

	req.Header.Set("X-Forwarded-For", "192.168.50.15")
	if got := tp.svc.clientAddr(req); got != "203.0.113.7:1234 (forwarded for 192.168.50.15)" {
		t.Errorf("clientAddr = %q", got)
	}
}

func TestClientAddrLookupDisabled(t *testing.T) {
	tp := newTestProxy(t, nil)
	tp.svc.clientResolver = newClientResolver(false)
	tp.svc.clientResolver.lookupFn = func(ip string, _ time.Duration) (string, error) {
		t.Fatal("lookup must not run when the resolver is disabled")
		return "", nil
	}

	req := httptest.NewRequest("GET", "/api/server/ping", nil)
	req.RemoteAddr = "172.23.0.3:57648"
	if got := tp.svc.clientAddr(req); got != "172.23.0.3:57648" {
		t.Errorf("clientAddr = %q", got)
	}
}

func TestClientIP(t *testing.T) {
	if got := clientIP("172.23.0.3:57648"); got != "172.23.0.3" {
		t.Fatalf("clientIP = %q, want 172.23.0.3", got)
	}
	if got := clientIP("[::1]:4242"); got != "::1" {
		t.Fatalf("clientIP = %q, want ::1", got)
	}
	if got := clientIP("garbage"); got != "garbage" {
		t.Fatalf("clientIP = %q, want garbage (passthrough)", got)
	}
}

// --- config -----------------------------------------------------------------

func TestLoadConfigClientHostnameLookup(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, machinesRoutesConfig), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ClientHostnameLookup {
		t.Error("client_hostname_lookup must default to true when absent")
	}

	// The key must sit in the top-level section, before any [[machines]] table.
	disabled := "client_hostname_lookup = false\n" + strings.TrimLeft(machinesRoutesConfig, "\n")
	cfg, err = LoadConfig(writeTempConfig(t, disabled), RealClock{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientHostnameLookup {
		t.Error("client_hostname_lookup = false must disable the lookup")
	}
}
