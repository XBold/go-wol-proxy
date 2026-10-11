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

// --- describeClient ----------------------------------------------------------

func newTestClientProxy(t *testing.T) *ProxyService {
	t.Helper()
	backend := newTestBackend(t, false)
	p, _, _, _, _, _ := setupProxy(t, backend, t.TempDir(), []string{"/docs"}, 100*time.Millisecond)
	p.clientResolver.enabled = true
	return p
}

func TestDescribeClient(t *testing.T) {
	p := newTestClientProxy(t)
	p.clientResolver.lookupFn = func(ip string, _ time.Duration) (string, error) {
		if ip == "172.23.0.3" {
			return "open-webui", nil
		}
		return "", errors.New("no PTR record")
	}

	req := httptest.NewRequest("POST", "http://192.168.50.80:9100/v1/chat/completions", nil)
	req.RemoteAddr = "172.23.0.3:57648"
	req.Host = "192.168.50.80:9100"
	req.Header.Set("User-Agent", "openai-python/1.59.3")
	req.Header.Set("X-Forwarded-For", "192.168.50.15")

	desc := p.describeClient(req)
	for _, want := range []string{
		"client: 172.23.0.3:57648",
		"hostname: open-webui",
		`user-agent: "openai-python/1.59.3"`,
		"x-forwarded-for: 192.168.50.15",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("describeClient = %q, missing %q", desc, want)
		}
	}
	for _, absent := range []string{"x-real-ip", "x-forwarded-host"} {
		if strings.Contains(desc, absent) {
			t.Errorf("describeClient = %q, should not contain %q", desc, absent)
		}
	}
}

func TestDescribeClientUnresolvableAndNoHeaders(t *testing.T) {
	p := newTestClientProxy(t)
	p.clientResolver.lookupFn = func(ip string, _ time.Duration) (string, error) {
		return "", errors.New("no PTR record")
	}

	req := httptest.NewRequest("GET", "http://192.168.50.80:9100/health", nil)
	req.RemoteAddr = "203.0.113.7:1234"

	desc := p.describeClient(req)
	if desc != "client: 203.0.113.7:1234" {
		t.Fatalf("describeClient = %q, want only the client address", desc)
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
