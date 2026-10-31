package netutil

import (
	"errors"
	"net/url"
)

// RedactURL reduces a URL to scheme and host for logs. Webhook and tracker
// URLs carry their credential in the path or query, so only the part that
// names the receiver is safe to write down.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparseable URL)"
	}
	return u.Scheme + "://" + u.Host
}

// StripURLError returns the cause wrapped in a *url.Error, dropping the
// request URL that net/http prints with every transport failure.
func StripURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}
