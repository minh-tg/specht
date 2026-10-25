package netutil

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// blockedPrefixes lists the special-purpose ranges that IsBlockedIP refuses on
// top of what net.IP already classifies (loopback, private, link-local,
// multicast, unspecified). IPv4 entries are matched after an IPv4-mapped IPv6
// address has been unmapped.
var blockedPrefixes = []netip.Prefix{
	// IPv4.
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	// IPv6. Several of these carry an IPv4 address inside, so a hostname that
	// resolves into them can reach an internal IPv4 host through a relay, a
	// Teredo server or a DNS64 gateway.
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("64:ff9b::/32"),    // NAT64, also covers 64:ff9b:1::/48
	netip.MustParsePrefix("::ffff:0:0:0/96"), // SIIT IPv4-translated (RFC 2765), not the IPv4-mapped ::ffff:0:0/96
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2001:2::/48"),     // benchmarking
	netip.MustParsePrefix("2001:10::/28"),    // ORCHID (deprecated)
	netip.MustParsePrefix("2001:20::/28"),    // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4
	netip.MustParsePrefix("3fff::/20"),       // documentation (RFC 9637)
	netip.MustParsePrefix("5f00::/16"),       // SRv6 SIDs
	netip.MustParsePrefix("fec0::/10"),       // site-local (deprecated)
}

// IsBlockedIP reports whether ip is a non-public address range (loopback, private,
// link-local, site-local, carrier-grade NAT, documentation, benchmarking,
// multicast, NAT64, SIIT, 6to4, Teredo, ORCHID, or an IPv4-compatible address).
func IsBlockedIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		// Neither 4 nor 16 bytes: not an address worth dialing.
		return true
	}
	addr = addr.Unmap()
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
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

// isInternalIP reports whether ip is a private, loopback or link-local address,
// the ranges an operator can legitimately host an internal service on.
func isInternalIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// SafeDialContextAllowHost behaves like SafeDialContext, except that a
// connection to allowedHost may reach private, loopback and link-local
// addresses. Every other host stays under the full block list, so a name taken
// from a remote document cannot use the exception. The host comparison is
// case-insensitive and ignores the port. An empty allowedHost allows nothing.
func SafeDialContextAllowHost(dialer *net.Dialer, allowLoopback bool, allowedHost string) func(context.Context, string, string) (net.Conn, error) {
	guarded := SafeDialContext(dialer, allowLoopback)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid destination %q: %w", address, err)
		}
		if allowedHost == "" || !strings.EqualFold(host, allowedHost) {
			return guarded(ctx, network, address)
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses", host)
		}
		for _, ip := range ips {
			if IsBlockedIP(ip) && !isInternalIP(ip) {
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
