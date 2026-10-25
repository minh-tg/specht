package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultRequestTimeout bounds one attempt of any API call except a report
// upload.
const DefaultRequestTimeout = 60 * time.Second

// IngestRequestTimeout bounds one attempt of POST /api/v1/reports. The server
// gives an upload 30s for the body, 2m to ingest and 30s to write the reply,
// 3m in all, and a busy server may first queue it. The client waits longer than
// that so a slow but successful ingest is not cut off on the client side.
const IngestRequestTimeout = 4 * time.Minute

// ingestPath is the report-upload endpoint that gets IngestRequestTimeout.
const ingestPath = "/api/v1/reports"

// RequestTimeout returns the per-attempt timeout for a request.
func RequestTimeout(req *http.Request) time.Duration {
	if req.Method == http.MethodPost && strings.TrimRight(req.URL.Path, "/") == ingestPath {
		return IngestRequestTimeout
	}
	return DefaultRequestTimeout
}

// NewTimeoutTransport wraps base so each round trip gets its own deadline
// from RequestTimeout. Unlike http.Client.Timeout, which covers every retry
// and backoff of a wrapping transport, the deadline here applies to one
// attempt, and a report upload gets the longer ingest timeout. A nil base
// means http.DefaultTransport.
func NewTimeoutTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &timeoutTransport{base: base}
}

type timeoutTransport struct {
	base http.RoundTripper
}

func (t *timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), RequestTimeout(req))
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	// The deadline also covers reading the body, so it is released only when
	// the caller closes it.
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelOnClose releases a per-attempt context once the body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
