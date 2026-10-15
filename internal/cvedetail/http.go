package cvedetail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
)

const (
	// maxResponseBytes caps one provider response. A single CVE record is a
	// few kilobytes; NVD's largest are well under a megabyte.
	maxResponseBytes = 2 << 20
	// userAgent is the only identifying header sent besides an API key.
	userAgent = "Specht"
	// defaultRetryAfter applies when a provider refuses for load without
	// saying how long to wait.
	defaultRetryAfter = 30 * time.Second
	// maxRetryAfter bounds a Retry-After a provider sends, so a bad header
	// cannot switch a provider off for days.
	maxRetryAfter = time.Hour
)

// IsHTTPSURL reports whether raw is an absolute https URL with a host.
func IsHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// NewHTTPClient returns the client providers use: no redirects, the given
// per-request timeout, and the SSRF-safe dialer that refuses private and
// link-local addresses. allowPrivate admits private addresses for an internal
// mirror the operator configured (CVE_DETAIL_ALLOW_PRIVATE_MIRROR); it still
// refuses redirects.
func NewHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	if !allowPrivate {
		return netutil.NewSafeHTTPClient(timeout)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: timeout}).DialContext},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
	}
}

// getJSON fetches one https URL and decodes the JSON body into v. Headers
// carry any API key; the URL never does. Statuses map to the package errors:
// 404 is ErrNotFound, 429 (and any code in rateLimited) is *RateLimitedError,
// anything else outside 200 is *HTTPStatusError. Errors never include the
// headers or the body.
func getJSON(ctx context.Context, client *http.Client, rawURL string, headers map[string]string, rateLimited []int, v any) error {
	if !IsHTTPSURL(rawURL) {
		return errors.New("cvedetail: provider URL must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return errors.New("cvedetail: build request")
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := client.Do(req)
	if err != nil {
		return transportError(err)
	}
	defer func() {
		// Drain a little so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests || containsInt(rateLimited, resp.StatusCode):
		return &RateLimitedError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	default:
		return &HTTPStatusError{Code: resp.StatusCode}
	}
	if err := netutil.DecodeJSONLimited(resp.Body, maxResponseBytes, v); err != nil {
		if errors.Is(err, netutil.ErrBodyTooLarge) {
			return err
		}
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errDecode
		}
		return transportError(err)
	}
	return nil
}

// transportError drops the request URL that net/http wraps around transport
// failures. The URL holds only the CVE identifier, but an error that names
// nothing but the cause is simpler to keep out of logs and storage.
func transportError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("cvedetail: request failed: %w", urlErr.Err)
	}
	return fmt.Errorf("cvedetail: request failed: %w", err)
}

// parseRetryAfter reads a Retry-After header in seconds or as an HTTP date,
// falling back to defaultRetryAfter and capping at maxRetryAfter.
func parseRetryAfter(v string, now time.Time) time.Duration {
	d := defaultRetryAfter
	if v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			d = time.Duration(secs) * time.Second
		} else if at, err := http.ParseTime(v); err == nil {
			d = at.Sub(now)
		}
	}
	if d <= 0 {
		d = time.Second
	}
	return min(d, maxRetryAfter)
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ParseTime reads the timestamp shapes providers use: RFC 3339 with or
// without a zone, and NVD's millisecond form without one (read as UTC).
func ParseTime(v string) *time.Time {
	if v == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05", "2006-01-02T15:04Z", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
