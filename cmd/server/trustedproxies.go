package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// catchAllProxyWarning returns a startup warning when TRUSTED_PROXIES holds a
// range that covers every address (0.0.0.0/0 or ::/0), or "" when it does not.
// Such a range makes every client a trusted proxy hop, so X-Forwarded-For and
// X-Forwarded-Proto from any internet client are believed.
func catchAllProxyWarning(trusted []netip.Prefix) string {
	var catchAll []string
	for _, p := range trusted {
		if p.Bits() == 0 {
			catchAll = append(catchAll, p.String())
		}
	}
	if len(catchAll) == 0 {
		return ""
	}
	return fmt.Sprintf("TRUSTED_PROXIES contains %s, which trusts every client: forwarded addresses and "+
		"protocols from any peer are believed, so per-IP limits can be dodged and HSTS and Secure cookies "+
		"forced; list only the addresses of your reverse proxies", strings.Join(catchAll, ", "))
}
