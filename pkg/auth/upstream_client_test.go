package auth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countNewConns runs rounds of concurrent GETs through client and returns how
// many TCP connections the server accepted.
func countNewConns(t *testing.T, client *http.Client, concurrency, rounds int) int64 {
	t.Helper()
	var accepted atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-User-Data", "{}")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			accepted.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	for range rounds {
		var wg sync.WaitGroup
		for range concurrency {
			wg.Go(func() {
				resp, err := client.Get(srv.URL)
				if !assert.NoError(t, err) {
					return
				}
				_, _ = resp.Body.Read(make([]byte, 16))
				_ = resp.Body.Close()
			})
		}
		wg.Wait()
	}
	return accepted.Load()
}

func TestUpstreamAuthHTTPClientReusesConnections(t *testing.T) {
	const concurrency, rounds = 32, 10

	// Go's default transport keeps 2 idle connections per host, so most calls
	// of every round open a new connection.
	defaultConns := countNewConns(t, &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}, concurrency, rounds)
	require.Greater(t, defaultConns, int64(concurrency*2), "default transport should churn connections")

	// Our client keeps the connections of the first round and reuses them.
	conns := countNewConns(t, newUpstreamAuthHTTPClient(), concurrency, rounds)
	t.Logf("new connections: default transport %d, upstream auth client %d", defaultConns, conns)
	assert.LessOrEqual(t, conns, int64(concurrency), "upstream auth client should reuse connections, opened %d (default transport opened %d)", conns, defaultConns)
}
