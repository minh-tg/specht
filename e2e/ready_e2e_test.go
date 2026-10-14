//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_ReadinessProbe checks the public probes on the real server against a
// real database: liveness says the process is up, readiness says it can serve.
func TestE2E_ReadinessProbe(t *testing.T) {
	for _, path := range []string{"/api/v1/health", "/api/v1/ready"} {
		status, raw := doJSON(t, http.MethodGet, path, "", nil)
		require.Equal(t, http.StatusOK, status, path+": "+string(raw))
	}

	ready := request[map[string]string](t, http.MethodGet, "/api/v1/ready", "", nil, http.StatusOK)
	require.Equal(t, "ready", ready["status"])
}
