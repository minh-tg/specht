package client

import (
	"errors"
	"fmt"
	"net/http"
)

// maxRedirects matches the redirect limit of net/http's default policy.
const maxRedirects = 10

// RefuseCrossOriginRedirect is an http.Client CheckRedirect that follows a
// redirect only while it keeps the scheme and host of the request it came
// from. The API does not redirect to another origin, and Go's default policy
// resends the Authorization header to the same host name over a downgraded
// scheme, which would put the bearer key on a plain http hop.
func RefuseCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	prev := via[len(via)-1].URL
	if req.URL.Scheme != prev.Scheme || req.URL.Host != prev.Host {
		return errors.New("refusing a redirect to another scheme or host: the API key would leave the configured server")
	}
	return nil
}

// withSameOriginRedirects returns hc itself when it already sets a redirect
// policy, and otherwise a copy that refuses cross-origin redirects.
func withSameOriginRedirects(hc *http.Client) *http.Client {
	if hc.CheckRedirect != nil {
		return hc
	}
	clone := *hc
	clone.CheckRedirect = RefuseCrossOriginRedirect
	return &clone
}
