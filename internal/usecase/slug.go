package usecase

import (
	"fmt"
	"regexp"
)

const (
	minProjectSlugLength = 3
	maxProjectSlugLength = 48
)

// slugPattern accepts lowercase alphanumeric groups joined by single hyphens.
// A dot would read as a file extension to the SPA fallback, and a slash or an
// uppercase letter would split one project across several URLs.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// reservedSlugs are the first path segments the server and the SPA own. A
// project with one of these slugs would shadow, or be shadowed by, a real
// route: /api/... never reaches the SPA, and /login resolves to the login
// page, not to a project named "login".
var reservedSlugs = map[string]struct{}{
	"admin":    {},
	"api":      {},
	"api-keys": {},
	"assets":   {},
	"ingest":   {},
	"login":    {},
	"projects": {},
	"register": {},
	"teams":    {},
}

// validateProjectSlug checks a slug on creation. Existing projects keep the
// slug they were created with.
func validateProjectSlug(slug string) error {
	if len(slug) < minProjectSlugLength || len(slug) > maxProjectSlugLength {
		return fmt.Errorf("%w: slug must be %d to %d characters", ErrInvalidSlug, minProjectSlugLength, maxProjectSlugLength)
	}
	if !slugPattern.MatchString(slug) {
		return fmt.Errorf("%w: slug may contain only lowercase letters, digits, and single hyphens between them", ErrInvalidSlug)
	}
	if _, reserved := reservedSlugs[slug]; reserved {
		return fmt.Errorf("%w: %q is reserved", ErrInvalidSlug, slug)
	}
	return nil
}
