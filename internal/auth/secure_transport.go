package auth

import (
	"context"
	"net/http"
)

// requestSecureKey carries the trusted-proxy transport verdict computed by the
// server's realIPMiddleware. It is a package-internal context key: only code
// that has consulted the trusted-proxy configuration (the router middleware)
// may stamp it. Clients can never set it, so a spoofed X-Forwarded-Proto from
// an untrusted peer cannot influence cookie security.
type requestSecureKey struct{}

// ContextWithSecureTransport records whether the request's transport is
// considered secure (TLS terminated either in-process or by a proxy inside the
// configured trusted ranges). Stamping false overrides any TLS on the request
// itself; stamping true is only ever done by code that verified a trusted
// proxy vouched for the connection.
func ContextWithSecureTransport(ctx context.Context, secure bool) context.Context {
	return context.WithValue(ctx, requestSecureKey{}, secure)
}

// SecureTransport reports whether the request arrived over a transport the
// server considers secure: an explicit middleware verdict wins, otherwise the
// request's own TLS state is used. It deliberately ignores client-supplied
// forwarding headers.
func SecureTransport(r *http.Request) bool {
	if v, ok := r.Context().Value(requestSecureKey{}).(bool); ok {
		return v
	}
	return r.TLS != nil
}

// secureCookie marks a cookie Secure when the request arrived over TLS, either
// directly or through a TLS-terminating proxy. The proxy case must not read
// X-Forwarded-Proto straight off the wire: the router's realIPMiddleware
// verifies the peer against the configured trusted proxies and stamps the
// verdict via ContextWithSecureTransport. See SecureTransport.
func secureCookie(r *http.Request, c *http.Cookie) *http.Cookie {
	c.Secure = SecureTransport(r)
	return c
}
