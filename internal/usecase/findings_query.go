package usecase

import (
	"errors"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/finding"
)

// ErrInvalidFindingQuery is returned for a sort key, direction, analysis
// state or search text the list endpoint does not accept. Handlers map it to
// a 400 and show the message.
var ErrInvalidFindingQuery = errors.New("invalid findings query")

type findingQueryError struct{ message string }

func (e *findingQueryError) Error() string        { return e.message }
func (e *findingQueryError) Is(target error) bool { return target == ErrInvalidFindingQuery }

func invalidFindingQuery(format string, args ...any) error {
	return &findingQueryError{message: fmt.Sprintf(format, args...)}
}

// maxFindingSearchLen bounds the free-text search so a request cannot make
// the database scan for an arbitrarily long pattern.
const maxFindingSearchLen = 100

// FindingSortKeys lists the accepted sort keys, default first.
var FindingSortKeys = []string{"severity", "first_seen", "last_seen", "title"}

type findingQuery struct {
	search  string
	sortKey string
	sortDir string
}

// normalize validates the sort, direction, analysis states and search text
// of a filter and resolves the defaults.
func (f FindingFilter) normalize() (findingQuery, error) {
	q := findingQuery{sortKey: f.Sort, sortDir: f.Dir}
	if q.sortKey == "" {
		q.sortKey = "severity"
	}
	if !containsString(FindingSortKeys, q.sortKey) {
		return q, invalidFindingQuery("sort must be one of %s", strings.Join(FindingSortKeys, ", "))
	}
	switch q.sortDir {
	case "":
		q.sortDir = "desc"
		if q.sortKey == "title" {
			q.sortDir = "asc"
		}
	case "asc", "desc":
	default:
		return q, invalidFindingQuery("dir must be asc or desc")
	}
	for _, state := range f.AnalysisStates {
		if _, ok := finding.ParseAnalysisState(state); !ok {
			valid := make([]string, len(finding.AllAnalysisStates))
			for i, s := range finding.AllAnalysisStates {
				valid[i] = string(s)
			}
			return q, invalidFindingQuery("analysis_state must be a comma list of %s", strings.Join(valid, ", "))
		}
	}
	search := strings.TrimSpace(f.Search)
	if len([]rune(search)) > maxFindingSearchLen {
		return q, invalidFindingQuery("q is longer than %d characters", maxFindingSearchLen)
	}
	q.search = escapeLike(search)
	return q, nil
}

// escapeLike escapes the LIKE metacharacters so user text matches literally.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
