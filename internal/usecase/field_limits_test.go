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

func TestCheckName(t *testing.T) {
	assert.NoError(t, checkName("name", "ci key"))
	assert.NoError(t, checkName("name", strings.Repeat("é", MaxNameChars)), "the limit counts characters, not bytes")
	assert.NoError(t, checkName("name", strings.Repeat("名", MaxNameChars)))

	for name, value := range map[string]string{
		"too long":      strings.Repeat("a", MaxNameChars+1),
		"huge":          strings.Repeat("a", 900_000),
		"ansi escape":   "ci\x1b[2J",
		"newline":       "ci\nkey",
		"tab":           "ci\tkey",
		"nul":           "ci\x00",
		"del":           "ci\x7f",
		"c1 control":    "ci\u009bkey",
		"multibyte max": strings.Repeat("名", MaxNameChars+1),
	} {
		err := checkName("name", value)
		assert.ErrorIs(t, err, ErrInvalidField, name)
	}
}

func TestCheckDescription(t *testing.T) {
	assert.NoError(t, checkDescription("description", "first line\r\nsecond\tline"))
	assert.NoError(t, checkDescription("description", strings.Repeat("a", MaxDescriptionChars)))
	assert.ErrorIs(t, checkDescription("description", strings.Repeat("a", MaxDescriptionChars+1)), ErrInvalidField)
	assert.ErrorIs(t, checkDescription("description", "a\x1b[31mred"), ErrInvalidField)
}

func TestCreateAPIKey_RefusesAnOverlongOrControlName(t *testing.T) {
	uc, got := keyCreatorHarness(t)
	for _, name := range []string{strings.Repeat("k", MaxNameChars+1), "ci\x1b[2J"} {
		_, err := uc.CreateAPIKey(adminCtx(), "my-app", name, "00000000-0000-0000-0000-000000000001", nil)
		assert.ErrorIs(t, err, ErrInvalidField)
	}
	assert.Empty(t, got.Name, "nothing was stored")

	_, err := uc.CreateAPIKey(adminCtx(), "my-app", "  "+strings.Repeat("k", MaxNameChars)+"  ", "00000000-0000-0000-0000-000000000001", nil)
	assert.NoError(t, err, "the limit applies after trimming")
}

func TestUpdateProject_RefusesAnOverlongOrControlNameOrDescription(t *testing.T) {
	for name, tc := range map[string]struct{ name, description *string }{
		"long name":           {name: strptr(strings.Repeat("n", MaxNameChars+1))},
		"escape in name":      {name: strptr("App\x1b[2J")},
		"long description":    {description: strptr(strings.Repeat("d", MaxDescriptionChars+1))},
		"escape in the notes": {description: strptr("notes\x1b[2J")},
	} {
		t.Run(name, func(t *testing.T) {
			pr := projectUpdateRepos()
			pr.updateFn = func(context.Context, string, port.ProjectUpdate) (port.Project, error) {
				t.Fatal("a refused update must not reach the store")
				return port.Project{}, nil
			}
			uc := New(Deps{Stores: &port.Stores{Projects: pr}})

			_, err := uc.UpdateProject(sessionCtx("admin-1", auth.RoleAdmin), "my-app", tc.name, tc.description, nil)

			assert.ErrorIs(t, err, ErrInvalidField)
		})
	}
}

func TestCreateProject_RefusesAnOverlongOrControlNameOrDescription(t *testing.T) {
	pr, _, _ := makeTestRepos()
	pr.createFn = func(context.Context, port.CreateProjectInput) (port.Project, error) {
		t.Fatal("a refused project must not reach the store")
		return port.Project{}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	ctx := sessionCtx("creator-1", auth.RoleAdmin)

	_, err := uc.CreateProject(ctx, strings.Repeat("n", MaxNameChars+1), "my-app", "", "creator-1")
	require.ErrorIs(t, err, ErrInvalidField)
	_, err = uc.CreateProject(ctx, "My App", "my-app", "bad\x1b[2J", "creator-1")
	require.ErrorIs(t, err, ErrInvalidField)
}
