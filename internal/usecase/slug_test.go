package usecase

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

func TestValidateProjectSlug(t *testing.T) {
	valid := []string{"abc", "my-app", "app2", "2fa-service", "a-b-c-d", strings.Repeat("a", 48)}
	for _, slug := range valid {
		assert.NoError(t, validateProjectSlug(slug), slug)
	}

	invalid := map[string]string{
		"too short":       "ab",
		"empty":           "",
		"too long":        strings.Repeat("a", 49),
		"dot":             "my.app",
		"uppercase":       "My-App",
		"underscore":      "my_app",
		"slash":           "team/app",
		"space":           "my app",
		"leading hyphen":  "-app",
		"trailing hyphen": "app-",
		"double hyphen":   "my--app",
		"non ascii":       "café-app",
		"reserved api":    "api",
		"reserved login":  "login",
		"reserved teams":  "teams",
		"reserved assets": "assets",
		"reserved keys":   "api-keys",
	}
	for name, slug := range invalid {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, validateProjectSlug(slug), ErrInvalidSlug)
		})
	}
}

func TestCreateProject_RejectsInvalidSlugBeforeTouchingTheStore(t *testing.T) {
	pr, _, _ := makeTestRepos()
	pr.createFn = func(ctx context.Context, arg port.CreateProjectInput) (port.Project, error) {
		t.Fatalf("store must not be called for slug %q", arg.Slug)
		return port.Project{}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})

	_, err := uc.CreateProject(sessionCtx("creator-1", auth.RoleAdmin), "Docs", "docs.site", "", "creator-1")
	require.ErrorIs(t, err, ErrInvalidSlug)
	assert.Contains(t, err.Error(), "lowercase letters, digits")
}
