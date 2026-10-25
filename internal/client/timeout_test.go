package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTimeoutTransportGivesReportUploadTheIngestWindow(t *testing.T) {
	cases := []struct {
		method, path string
		want         time.Duration
	}{
		{http.MethodPost, "/api/v1/reports", IngestRequestTimeout},
		{http.MethodGet, "/api/v1/reports", DefaultRequestTimeout},
		{http.MethodGet, "/api/v1/projects/p/gate", DefaultRequestTimeout},
		{http.MethodPost, "/api/v1/projects/p/waivers", DefaultRequestTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var remaining time.Duration
			base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				deadline, ok := req.Context().Deadline()
				require.True(t, ok, "every attempt has a deadline")
				remaining = time.Until(deadline)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: req}, nil
			})
			req, err := http.NewRequest(tc.method, "http://example.test"+tc.path, nil)
			require.NoError(t, err)
			resp, err := NewTimeoutTransport(base).RoundTrip(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.InDelta(t, tc.want.Seconds(), remaining.Seconds(), 1)
		})
	}
}

func TestTimeoutTransportKeepsTheBodyReadableUntilClosed(t *testing.T) {
	var attemptCtx context.Context
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attemptCtx = req.Context()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
	})
	req, err := http.NewRequest(http.MethodGet, "http://example.test/api/v1/projects", nil)
	require.NoError(t, err)
	resp, err := NewTimeoutTransport(base).RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, attemptCtx.Err(), "the deadline must outlive RoundTrip while the body is read")
	require.NoError(t, resp.Body.Close())
	assert.ErrorIs(t, attemptCtx.Err(), context.Canceled, "closing the body releases the attempt")
}
