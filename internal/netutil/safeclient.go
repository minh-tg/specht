package netutil

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// IsBlockedIP reports whether ip is a non-public address range (loopback, private,
// link-local, carrier-grade NAT, documentation, benchmarking, multicast, or NAT64).
func IsBlockedIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	v4 := ip.To4()
	if v4 != nil {
		// Carrier-grade NAT, benchmarking, and documentation ranges are not
		// routable public service addresses and must not be SSRF targets.
		return (v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127) ||
			(v4[0] == 198 && v4[1] >= 18 && v4[1] <= 19) ||
			(v4[0] == 192 && v4[1] == 0 && v4[2] == 0) ||
			(v4[0] >= 240) ||
			(v4[0] == 192 && v4[1] == 0 && v4[2] == 2) ||
			(v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
			(v4[0] == 203 && v4[1] == 0 && v4[2] == 113)
	}
	// IPv6 documentation range (2001:db8::/32).
	if len(ip) == net.IPv6len && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return true
	}
	// IPv6 NAT64 well-known prefix (64:ff9b::/96).
	if len(ip) == net.IPv6len && ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b {
		return true
	}
	return false
}

// IsLoopbackHost reports whether host evaluates to localhost or a loopback IP.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SafeDialContext resolves the destination before connecting and refuses local,
// private, link-local, multicast, and other non-public address ranges.
// The allowLoopback parameter determines whether loopback addresses are admitted.
func SafeDialContext(dialer *net.Dialer, allowLoopback bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid destination %q: %w", address, err)
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses", host)
		}
		for _, ip := range ips {
			if IsBlockedIP(ip) && !(allowLoopback && ip.IsLoopback()) {
				return nil, fmt.Errorf("refusing connection to non-public address %q", ip)
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

// SafeDialContextDynamic inspects the destination host at dial time.
// If the destination host requested is explicitly a loopback host (e.g. localhost or 127.0.0.1
// in development/tests), loopback connection is allowed. If the destination host is NOT a loopback
// host (including external hostnames that resolve to loopback via DNS rebinding), all non-public/private/loopback
// IPs are rejected.
func SafeDialContextDynamic(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid destination %q: %w", address, err)
		}
		allowLoopback := IsLoopbackHost(host)
		return SafeDialContext(dialer, allowLoopback)(ctx, network, address)
	}
}

// NewSafeTransport returns an http.Transport configured with SafeDialContextDynamic.
func NewSafeTransport(timeout time.Duration) *http.Transport {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Transport{
		DialContext: SafeDialContextDynamic(&net.Dialer{Timeout: timeout}),
	}
}

// NewSafeHTTPClient returns an http.Client with SSRF protection and redirect blocking.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: NewSafeTransport(timeout),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirects are not allowed")
		},
	}
}

// SafeHTTPClientForURL creates an http.Client safe for the given target URL.
func SafeHTTPClientForURL(rawURL string, timeout time.Duration) *http.Client {
	allowLoopback := false
	if u, err := url.Parse(rawURL); err == nil {
		allowLoopback = IsLoopbackHost(u.Hostname())
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: SafeDialContext(&net.Dialer{Timeout: timeout}, allowLoopback),
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirects are not allowed")
		},
	}
}
