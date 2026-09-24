// API Security Tests for OWASP API Security Top 10:2023.
// Category: API7:2023 — Server-Side Request Forgery.
//
// Pins the C-11 (ASVS_L2) plugin HTTP host-library SSRF defences:
//   - Loopback / RFC1918 / link-local / cloud-metadata IPs are refused
//     pre-dial, even when the URL hostname resolves to them via DNS.
//   - Scheme allow-list rejects file://, ftp://, gopher://, …
//   - Redirect targets are re-validated, so a public origin cannot bounce
//     the request into a private network.
//   - DNS rebinding cannot bypass the IP check because we dial the
//     resolved IP, not the original hostname.
//   - TimeoutSeconds is clamped to the operator-configured ceiling.
//   - Response headers go through an allowlist (Set-Cookie, Authorization
//     etc. never reach the plugin).
//
// Reference: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/
package hostlibrary

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	sdkhttp "github.com/gameap/gameap/pkg/plugin/sdk/http"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strictTestConfig is the production-shaped config: SSRF on, https-only,
// no host bypass. Used by SSRF regression tests so the result matches a
// real deployment.
func strictTestConfig() HTTPConfig {
	return HTTPConfig{
		BlockPrivateIPs: true,
		AllowedSchemes:  []string{"http", "https"}, // http only for httptest reachability
		MaxTimeout:      5 * time.Second,
		MaxRedirects:    3,
	}
}

var errFakeResolverNoEntry = errors.New("fake resolver has no entry")

// fakeResolver lets a test pretend a hostname resolves to a specific IP.
type fakeResolver struct {
	mapping map[string][]netip.Addr
	calls   atomic.Int32
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.calls.Add(1)

	ips, ok := f.mapping[host]
	if !ok {
		return nil, errors.Wrapf(errFakeResolverNoEntry, "host %q", host)
	}

	return ips, nil
}

// TestHTTPService_SSRF_BlocksLoopback — OWASP API7:2023 — strict config
// must refuse to dial 127.0.0.1 even when the request URL points there
// directly. Without this, a malicious plugin can reach panel-internal
// services (Redis, sqlite admin, the local metrics endpoint).
func TestHTTPService_SSRF_BlocksLoopback(t *testing.T) {
	t.Parallel()
	svc := NewHTTPService(strictTestConfig())

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    "http://127.0.0.1:9999/secret",
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Contains(t, *resp.Error, "blocked", "error must surface the SSRF block reason")
	assert.Contains(t, *resp.Error, "loopback")
}

// TestHTTPService_SSRF_BlocksIPv4MappedUnspecified — OWASP API7:2023 —
// ::ffff:0.0.0.0 is dialed as plain IPv4 0.0.0.0, which the OS routes to the
// local host. The filter must see through the mapping; otherwise the default
// config lets a plugin into every loopback service.
func TestHTTPService_SSRF_BlocksIPv4MappedUnspecified(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)

	svc := NewHTTPService(strictTestConfig())

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    "http://" + net.JoinHostPort("::ffff:0.0.0.0", port) + "/",
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error, "the request reached the loopback server with status %d", resp.StatusCode)
	assert.Contains(t, *resp.Error, "blocked")
	assert.Contains(t, *resp.Error, "unspecified")
	assert.Zero(t, hits.Load(), "a blocked target must never receive the request")
}

// TestHTTPService_SSRF_BlocksRFC1918 — OWASP API7:2023 — private IPs are
// blocked. Covers 10/8, 172.16/12, 192.168/16.
func TestHTTPService_SSRF_BlocksRFC1918(t *testing.T) {
	t.Parallel()
	cases := []string{
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.1.1/",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			svc := NewHTTPService(strictTestConfig())

			resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
				Url:    target,
				Method: "GET",
			})

			require.NoError(t, err)
			require.NotNil(t, resp.Error)
			assert.Contains(t, *resp.Error, "private")
		})
	}
}

// TestHTTPService_SSRF_BlocksCloudMetadata — OWASP API7:2023 — the AWS /
// Alibaba IMDS endpoints must be rejected. Even when the operator turns
// off BlockPrivateIPs, cloud-metadata IPs stay blocked.
func TestHTTPService_SSRF_BlocksCloudMetadata(t *testing.T) {
	t.Parallel()
	for _, blockPrivate := range []bool{true, false} {
		t.Run(fmt.Sprintf("block_private_%v", blockPrivate), func(t *testing.T) {
			t.Parallel()
			cfg := strictTestConfig()
			cfg.BlockPrivateIPs = blockPrivate

			svc := NewHTTPService(cfg)

			for _, target := range []string{
				"http://169.254.169.254/latest/meta-data/",
				"http://100.100.100.200/",
				// IPv6 spellings that reach the same endpoints: IPv4-mapped
				// (dialed as plain IPv4), NAT64, 6to4 and IPv4-compatible.
				"http://[::ffff:169.254.169.254]/latest/meta-data/",
				"http://[::ffff:100.100.100.200]/",
				"http://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
				"http://[2002:a9fe:a9fe::]/latest/meta-data/",
				"http://[::a9fe:a9fe]/latest/meta-data/",
				// Local-use NAT64 (/96 and /48 layouts), Teredo, SIIT.
				"http://[64:ff9b:1::a9fe:a9fe]/latest/meta-data/",
				"http://[64:ff9b:1:a9fe:a9:fe00::]/latest/meta-data/",
				"http://[2001:0:4136:e378:8000:63bf:5601:5601]/latest/meta-data/",
				"http://[::ffff:0:a9fe:a9fe]/latest/meta-data/",
				// AWS over IPv6, plain and zoned.
				"http://[fd00:ec2::254]/latest/meta-data/",
				"http://[fd00:ec2::254%25eth0]/latest/meta-data/",
				// Endpoints of other providers.
				"http://169.254.170.2/v2/credentials/",
				"http://[fd20:ce::254]/computeMetadata/v1/",
				"http://168.63.129.16/machine?comp=goalstate",
			} {
				resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
					Url:    target,
					Method: "GET",
				})

				require.NoError(t, err)
				require.NotNil(t, resp.Error, "%s must be blocked", target)
				assert.Contains(t, *resp.Error, "cloud_metadata",
					"%s must be blocked regardless of BlockPrivateIPs=%v", target, blockPrivate)
			}
		})
	}
}

// TestHTTPService_SSRF_BlocksHostnameResolvingToMappedMetadata — OWASP
// API7:2023 — the pure-Go resolver returns /etc/hosts IPv4 entries in their
// 16-byte form, so a name like metadata.google.internal comes back as
// ::ffff:169.254.169.254. It must stay blocked with BlockPrivateIPs off.
func TestHTTPService_SSRF_BlocksHostnameResolvingToMappedMetadata(t *testing.T) {
	t.Parallel()
	resolver := &fakeResolver{
		mapping: map[string][]netip.Addr{
			"metadata.google.internal": {netip.MustParseAddr("::ffff:169.254.169.254")},
		},
	}

	cfg := strictTestConfig()
	cfg.BlockPrivateIPs = false

	svc := newHTTPService(cfg, resolver, &net.Dialer{})

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    "http://metadata.google.internal/computeMetadata/v1/",
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Contains(t, *resp.Error, "ip=169.254.169.254 reason=cloud_metadata requested=::ffff:169.254.169.254")
}

// TestHTTPService_SSRF_IgnoresEnvironmentProxy — OWASP API7:2023 — through
// an HTTP(S)_PROXY the transport would dial only the proxy, and the proxy
// would then fetch any target for the plugin, cloud metadata included. The
// plugin transport must dial every target itself.
func TestHTTPService_SSRF_IgnoresEnvironmentProxy(t *testing.T) {
	var hits atomic.Int32

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)

	// The proxy itself would pass the gate: it is loopback and allow-listed.
	cfg := strictTestConfig()
	cfg.AllowedHosts = []string{"127.0.0.1"}

	svc := NewHTTPService(cfg)

	transport, ok := svc.client(context.Background()).Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, transport.Proxy)

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/admin",
	} {
		resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
			Url:    target,
			Method: "GET",
		})

		require.NoError(t, err)
		require.NotNil(t, resp.Error, "%s was answered through the proxy", target)
		assert.Contains(t, *resp.Error, "target ip is blocked")
	}

	assert.Zero(t, hits.Load(), "no request may go through the proxy")
}

// TestHTTPService_SSRF_BlocksHostnameResolvingToPrivate — OWASP API7:2023 —
// a public hostname whose A-record points into RFC1918 is blocked.
// Without per-IP validation post-resolution, an attacker could host a DNS
// name that maps to a private IP and bypass naive URL-only filters.
func TestHTTPService_SSRF_BlocksHostnameResolvingToPrivate(t *testing.T) {
	t.Parallel()
	resolver := &fakeResolver{
		mapping: map[string][]netip.Addr{
			"attacker.example": {netip.MustParseAddr("10.0.0.50")},
		},
	}
	svc := newHTTPService(strictTestConfig(), resolver, &net.Dialer{})

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    "http://attacker.example/",
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Contains(t, *resp.Error, "private")
	assert.Equal(t, int32(1), resolver.calls.Load(), "exactly one DNS lookup expected")
}

// TestHTTPService_SSRF_RejectsBlockedScheme — OWASP API7:2023 — schemes
// outside the allow-list (file://, ftp://, gopher://, …) must be refused
// before any IO.
func TestHTTPService_SSRF_RejectsBlockedScheme(t *testing.T) {
	t.Parallel()
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com/",
		"gopher://example.com/",
		"data:text/plain;base64,aGVsbG8=",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			svc := NewHTTPService(strictTestConfig())

			resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
				Url:    target,
				Method: "GET",
			})

			require.NoError(t, err)
			require.NotNil(t, resp.Error)
			assert.Contains(t, *resp.Error, "scheme not allowed")
		})
	}
}

// TestHTTPService_SSRF_BlocksRedirectIntoPrivate — OWASP API7:2023 — a
// public origin that issues a 302 Location: http://10.0.0.1/ must not
// follow into RFC1918. CheckRedirect re-validates every hop.
func TestHTTPService_SSRF_BlocksRedirectIntoPrivate(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.0.0.42/secret", http.StatusFound)
	}))
	defer server.Close()

	// Allow the loopback (httptest) host so we get past the initial dial,
	// then prove the redirect target is rejected.
	cfg := strictTestConfig()
	cfg.AllowedHosts = []string{"127.0.0.1"}

	svc := NewHTTPService(cfg)

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	// CheckRedirect returns errBlockedTarget; the wrapped string contains
	// either "blocked" or "private" depending on which validator fired
	// first. Either is acceptable evidence the redirect was refused.
	if !assert.True(t,
		containsAny(*resp.Error, "blocked", "private"),
		"redirect rejection must mention the SSRF block; got %q", *resp.Error,
	) {
		return
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if assertContains(s, n) {
			return true
		}
	}

	return false
}

func assertContains(haystack, needle string) bool {
	return len(needle) <= len(haystack) && (len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}

	return -1
}

// TestHTTPService_SSRF_TimeoutCap — OWASP API7:2023 — a plugin requesting
// a 1-hour timeout must be clamped to the operator-configured ceiling.
// The clamp is observable as: a server that hangs longer than the cap
// causes the fetch to error out within the cap window.
func TestHTTPService_SSRF_TimeoutCap(t *testing.T) {
	t.Parallel()
	cfg := strictTestConfig()
	cfg.MaxTimeout = time.Second // 1s ceiling
	cfg.AllowedHosts = []string{"127.0.0.1"}

	// Server that never responds.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, accErr := listener.Accept()
		if accErr != nil {
			return
		}
		// Hold the connection open without writing.
		<-make(chan struct{})
		_ = conn.Close()
	}()

	svc := NewHTTPService(cfg)

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:            "http://" + listener.Addr().String() + "/",
		Method:         "GET",
		TimeoutSeconds: 3600, // attempt to override
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
}

// TestHTTPService_SSRF_AllowedHostBypassesBlocklist — OWASP API7:2023 —
// an operator opt-in allow-list lets a hostname reach a private IP. This
// is the documented escape hatch for internal infrastructure (e.g. an
// in-VPC plugin store mirror).
func TestHTTPService_SSRF_AllowedHostBypassesBlocklist(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	cfg := strictTestConfig()
	cfg.AllowedHosts = []string{"127.0.0.1"} // httptest binds to loopback

	svc := NewHTTPService(cfg)

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "GET",
	})

	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Equal(t, int32(200), resp.StatusCode)
}

// TestHTTPService_SSRF_AllowedHostCannotBypassMetadata — OWASP API7:2023 —
// even an explicit allow-list cannot unlock the cloud-metadata IPs. This
// pins the layered defence: operator allow-lists are for internal
// hostnames, not for IMDS.
func TestHTTPService_SSRF_AllowedHostCannotBypassMetadata(t *testing.T) {
	t.Parallel()
	resolver := &fakeResolver{
		mapping: map[string][]netip.Addr{
			"imds.attacker.example": {netip.MustParseAddr("169.254.169.254")},
		},
	}

	cfg := strictTestConfig()
	cfg.AllowedHosts = []string{"imds.attacker.example"}

	svc := newHTTPService(cfg, resolver, &net.Dialer{})

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    "http://imds.attacker.example/latest/meta-data/",
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Contains(t, *resp.Error, "cloud_metadata",
		"cloud-metadata IPs must never be reachable, even via an explicit allow-list")
}

// TestHTTPService_SSRF_ResponseHeaderAllowlist — OWASP API7:2023 —
// Set-Cookie, Authorization and other sensitive response headers issued
// by a reachable origin must not reach the plugin. The plugin sees only
// the curated allowlist.
func TestHTTPService_SSRF_ResponseHeaderAllowlist(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=secret-cookie-value; HttpOnly")
		w.Header().Set("Authorization", "Bearer leaked-token")
		w.Header().Set("WWW-Authenticate", "Basic realm=corp")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	}))
	defer server.Close()

	cfg := strictTestConfig()
	cfg.AllowedHosts = []string{"127.0.0.1"}

	svc := NewHTTPService(cfg)

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "GET",
	})

	require.NoError(t, err)
	assert.Nil(t, resp.Error)

	assert.Equal(t, "text/plain", resp.Headers["Content-Type"], "default allowlist must pass Content-Type")
	assert.Equal(t, "no-store", resp.Headers["Cache-Control"], "default allowlist must pass Cache-Control")

	assert.Empty(t, resp.Headers["Set-Cookie"], "Set-Cookie must NEVER reach the plugin")
	assert.Empty(t, resp.Headers["Authorization"], "Authorization must NEVER reach the plugin")
	assert.Empty(t, resp.Headers["Www-Authenticate"], "WWW-Authenticate must NEVER reach the plugin")
}

// TestHTTPService_SSRF_ResponseHeaderAllowlistOperatorExtras — OWASP
// API7:2023 — the operator can additively allow extra headers (X-Trace-ID
// for an internal API), but the dangerous defaults remain stripped.
func TestHTTPService_SSRF_ResponseHeaderAllowlistOperatorExtras(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Trace-ID", "trace-abc")
		w.Header().Set("Set-Cookie", "session=secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := strictTestConfig()
	cfg.AllowedHosts = []string{"127.0.0.1"}
	cfg.ResponseHeaderAllowlist = []string{"X-Trace-ID"}

	svc := NewHTTPService(cfg)

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "GET",
	})

	require.NoError(t, err)
	assert.Equal(t, "trace-abc", resp.Headers["X-Trace-Id"], "operator-allow-listed header must pass through")
	assert.Empty(t, resp.Headers["Set-Cookie"], "Set-Cookie remains stripped even when operator adds other extras")
}

// TestHTTPService_SSRF_MaxRedirectsCap — OWASP API7:2023 — a redirect
// chain longer than the configured ceiling must be refused so an
// attacker cannot waste resources or evade per-hop logging.
func TestHTTPService_SSRF_MaxRedirectsCap(t *testing.T) {
	t.Parallel()
	hopCount := 0
	var serverURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hopCount++
		http.Redirect(w, r, serverURL+"/", http.StatusFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	cfg := strictTestConfig()
	cfg.AllowedHosts = []string{"127.0.0.1"}
	cfg.MaxRedirects = 2

	svc := NewHTTPService(cfg)

	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Contains(t, *resp.Error, "too many redirects")
}
