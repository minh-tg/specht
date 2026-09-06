package domain

import (
	"fmt"
	"strings"
)

// RepoRef is a structured repository identity using a provider-scoped URI.
//
// Format: provider://owner/repo
//
//   - provider: the code-hosting provider (e.g. "github", "gitlab", "bitbucket")
//   - owner:    the org/user namespace
//   - repo:     the repository name
//
// This gives every target a stable, unambiguous identity that the CI/CD adapter
// and gate can match against regardless of which provider hosts the repository.
//
// unified provider:// URI model for repository identity.
type RepoRef struct {
	Provider string
	Owner    string
	Repo     string
}

// ParseRepoRef parses a provider://owner/repo URI into a RepoRef.
// An empty string yields a zero RepoRef (no error).
func ParseRepoRef(s string) (RepoRef, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return RepoRef{}, nil
	}
	sep := strings.Index(s, "://")
	if sep < 0 {
		return RepoRef{}, fmt.Errorf("repo ref must use provider://owner/repo format")
	}
	provider := s[:sep]
	rest := s[sep+3:]
	// Split into exactly 2 parts: owner and repo. The owner may contain
	// slashes (e.g. GitLab subgroups: "org/group").
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return RepoRef{}, fmt.Errorf("repo ref must be provider://owner/repo (got %q)", s)
	}
	owner := rest[:slash]
	repo := rest[slash+1:]
	if provider == "" || owner == "" || repo == "" {
		return RepoRef{}, fmt.Errorf("repo ref must be provider://owner/repo (got %q)", s)
	}
	return RepoRef{
		Provider: provider,
		Owner:    owner,
		Repo:     repo,
	}, nil
}

// String renders the RepoRef back to provider://owner/repo form.
// An empty RepoRef renders as "".
func (r RepoRef) String() string {
	if r.Provider == "" && r.Owner == "" && r.Repo == "" {
		return ""
	}
	return r.Provider + "://" + r.Owner + "/" + r.Repo
}

// Provider returns the hosting provider (e.g. "github", "gitlab").
func (r RepoRef) GetProvider() string { return r.Provider }

// FullName returns owner/repo (without provider prefix).
func (r RepoRef) FullName() string { return r.Owner + "/" + r.Repo }
