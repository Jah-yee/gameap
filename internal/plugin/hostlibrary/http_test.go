package hostlibrary

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdkhttp "github.com/gameap/gameap/pkg/plugin/sdk/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissiveTestConfig returns an HTTPConfig that lets httptest.NewServer
// targets reach the loopback interface — needed for any non-SSRF test
// that exercises plain HTTP behaviour. Production deployments must NOT
// use this configuration; production callers source the config from
// internal/config Plugin.HTTP which keeps BlockPrivateIPs=true.
func permissiveTestConfig() HTTPConfig {
	return HTTPConfig{
		BlockPrivateIPs: false,
		AllowedSchemes:  []string{"http", "https"},
		MaxTimeout:      60 * time.Second,
		MaxRedirects:    5,
	}
}

func TestHTTPService_Fetch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		setupServer    func() *httptest.Server
		method         string
		body           []byte
		headers        map[string]string
		wantStatusCode int32
		wantBody       string
		wantError      string
	}{
		{
			name: "get_request_success",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("Hello, World!"))
				}))
			},
			method:         "GET",
			wantStatusCode: 200,
			wantBody:       "Hello, World!",
		},
		{
			name: "post_request_with_body",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						w.WriteHeader(http.StatusMethodNotAllowed)

						return
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"status":"created"}`))
				}))
			},
			method:         "POST",
			body:           []byte(`{"name":"test"}`),
			wantStatusCode: 201,
			wantBody:       `{"status":"created"}`,
		},
		{
			name: "custom_headers_sent",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("X-Custom-Header") == "custom-value" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte("header received"))

						return
					}
					w.WriteHeader(http.StatusBadRequest)
				}))
			},
			method: "GET",
			headers: map[string]string{
				"X-Custom-Header": "custom-value",
			},
			wantStatusCode: 200,
			wantBody:       "header received",
		},
		{
			name: "response_headers_returned",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("X-Response-Header", "response-value")
					w.WriteHeader(http.StatusOK)
				}))
			},
			method:         "GET",
			wantStatusCode: 200,
		},
		{
			name: "status_code_returned",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte("not found"))
				}))
			},
			method:         "GET",
			wantStatusCode: 404,
			wantBody:       "not found",
		},
		{
			name: "internal_server_error",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("internal error"))
				}))
			},
			method:         "GET",
			wantStatusCode: 500,
			wantBody:       "internal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := tt.setupServer()
			defer server.Close()

			svc := NewHTTPService(permissiveTestConfig())
			resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
				Url:     server.URL,
				Method:  tt.method,
				Body:    tt.body,
				Headers: tt.headers,
			})

			require.NoError(t, err)

			if tt.wantError != "" {
				require.NotNil(t, resp.Error)
				assert.Contains(t, *resp.Error, tt.wantError)

				return
			}

			assert.Nil(t, resp.Error)
			assert.Equal(t, tt.wantStatusCode, resp.StatusCode)

			if tt.wantBody != "" {
				assert.Equal(t, tt.wantBody, string(resp.Body))
			}
		})
	}
}

func TestHTTPService_Fetch_InvalidURL(t *testing.T) {
	t.Parallel()
	svc := NewHTTPService(permissiveTestConfig())
	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    "://invalid-url",
		Method: "GET",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Contains(t, *resp.Error, "missing protocol scheme")
}

func TestHTTPService_Fetch_UnreachableHost(t *testing.T) {
	t.Parallel()
	svc := NewHTTPService(permissiveTestConfig())
	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:            "http://localhost:59999",
		Method:         "GET",
		TimeoutSeconds: 1,
	})

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
}

// Pinned by ASVS_L2 C-11: only response headers in the curated allowlist
// (and any operator-added extras) reach the plugin. Arbitrary X-*
// response headers from a reached origin must be stripped so a plugin
// cannot read credentials or fingerprints set by a third-party endpoint.
func TestHTTPService_Fetch_ResponseHeaders(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom-Response", "test-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()

	svc := NewHTTPService(permissiveTestConfig())
	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "GET",
	})

	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Equal(t, "application/json", resp.Headers["Content-Type"],
		"Content-Type is in the default allowlist and must pass through")
	assert.Empty(t, resp.Headers["X-Custom-Response"],
		"X-* headers are not in the default allowlist and must be stripped")
}

func TestHTTPService_Fetch_CustomTimeout(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewHTTPService(permissiveTestConfig())
	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:            server.URL,
		Method:         "GET",
		TimeoutSeconds: 60,
	})

	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Equal(t, int32(200), resp.StatusCode)
}

func TestHTTPService_Fetch_PutMethod(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("put success"))

			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	svc := NewHTTPService(permissiveTestConfig())
	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "PUT",
		Body:   []byte(`{"update":"data"}`),
	})

	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Equal(t, int32(200), resp.StatusCode)
	assert.Equal(t, "put success", string(resp.Body))
}

func TestHTTPService_Fetch_DeleteMethod(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)

			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	svc := NewHTTPService(permissiveTestConfig())
	resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
		Url:    server.URL,
		Method: "DELETE",
	})

	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Equal(t, int32(204), resp.StatusCode)
}

// Every Fetch builds its own transport, so a kept-alive connection would stay
// open with nothing left to reuse or close it, and a plugin looping on Fetch
// could exhaust the panel's file descriptors. Every connection, redirect hops
// included, must close once its response is read.
func TestHTTPService_Fetch_ClosesConnections(t *testing.T) {
	t.Parallel()

	var open atomic.Int32

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/", http.StatusFound)

			return
		}

		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			open.Add(1)
		}

		if state == http.StateClosed {
			open.Add(-1)
		}
	}
	server.Start()
	defer server.Close()

	svc := NewHTTPService(permissiveTestConfig())

	for range 5 {
		resp, err := svc.Fetch(context.Background(), &sdkhttp.HTTPFetchRequest{
			Url:    server.URL + "/redirect",
			Method: "GET",
		})

		require.NoError(t, err)
		require.Nil(t, resp.Error)
	}

	assert.Eventually(t, func() bool { return open.Load() == 0 }, 2*time.Second, 10*time.Millisecond,
		"connections stayed open after the fetches returned")
}

func TestNewHTTPHostLibrary(t *testing.T) {
	t.Parallel()
	lib := NewHTTPHostLibrary(permissiveTestConfig())

	assert.NotNil(t, lib)
	assert.NotNil(t, lib.impl)
}
