package domain

import (
	"net/url"
	"strings"
)

// MaxLinkURLBytes and MaxPullRequestTitleBytes bound where a report came from:
// the repository and CI run URLs, and the pull request title.
const (
	MaxLinkURLBytes          = 2048
	MaxPullRequestTitleBytes = 512
)

// LinkURLProblem says why s cannot be stored as a link the UI renders, or
// returns "" when it can or is empty. Only absolute http(s) URLs with a host
// pass, and none with user info: GitLab's CI_REPOSITORY_URL carries the job
// token there, and a link must never store a credential. The scheme is
// compared as written, because the database check is case sensitive and
// url.Parse would accept HTTPS:// too. The message never quotes s.
func LinkURLProblem(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > MaxLinkURLBytes {
		return "must be at most 2048 bytes"
	}
	u, err := url.Parse(s)
	switch {
	case !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://"),
		err != nil, u.Host == "", u.Opaque != "":
		return "must be an absolute http or https URL"
	case u.User != nil:
		return "must not contain a user name or password"
	case strings.ContainsFunc(s, func(r rune) bool { return r == ' ' || r < 0x20 || r == 0x7f }):
		return "must not contain spaces or control characters"
	}
	return ""
}
