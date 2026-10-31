//go:build integration

package repo

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

// refreshRaceRuns is how many times the refresh/credential-change race runs.
// One run only overlaps the two when the refresh lands inside the change's
// transaction, so the count has to be high enough to hit it every time the
// guard is missing. The refresher keeps refreshing while the change runs, which
// makes a run overlap on its own; the loop is the margin.
const refreshRaceRuns = 30

const raceOldPassword = "old-password-1234"

// raceUsecases wires the real stores to the real use cases.
func raceUsecases(t *testing.T, repos *Repos) *usecase.Usecases {
	t.Helper()
	jwt, err := auth.NewJWTAuthenticator("race-secret-for-tests-1234567890")
	require.NoError(t, err)
	return usecase.New(usecase.Deps{
		Stores:    NewPortStores(repos.pool),
		Tokens:    jwt,
		Passwords: auth.NewPasswordHasher(),
	})
}

// newPasswordUser creates an account whose password the use cases can verify.
func newPasswordUser(t *testing.T, repos *Repos, password string) port.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)
	row, err := repos.Users.Create(context.Background(), "race-"+uuid.NewString()+"@test.com",
		pgtype.Text{Valid: false}, pgtype.Text{String: hash, Valid: true})
	require.NoError(t, err)
	return userToPort(row)
}

// A client refreshes in a loop while the owner changes the password. When the
// change commits, no token that was refreshed before it may still work, and
// the only live token left is the one the change itself issued.
func TestRefreshRacingAPasswordChangeLeavesNoUsableSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	uc := raceUsecases(t, repos)

	for run := 0; run < refreshRaceRuns; run++ {
		user := newPasswordUser(t, repos, raceOldPassword)
		login, err := uc.Login(ctx, user.Email, raceOldPassword)
		require.NoError(t, err)

		changed := make(chan struct{})
		warm := make(chan struct{})
		var latest string
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := login.RefreshToken
			var once sync.Once
			for {
				select {
				case <-changed:
					latest = token
					return
				default:
				}
				resp, err := uc.Refresh(ctx, token)
				if err != nil {
					// The change revoked the chain; wait for it to finish.
					<-changed
					latest = token
					return
				}
				token = resp.RefreshToken
				once.Do(func() { close(warm) })
			}
		}()

		<-warm
		_, err = uc.ChangePassword(ctx, user.ID, raceOldPassword, "new-password-5678")
		close(changed)
		wg.Wait()
		require.NoError(t, err, "run %d", run)

		_, err = uc.Refresh(ctx, latest)
		require.Error(t, err, "run %d: the last refreshed token must not survive the change", run)
		assert.Equal(t, 1, liveRefreshTokens(t, repos, user.ID),
			"run %d: only the session the change issued may be live", run)
	}
}

func rotationInput(user port.User, familyID string) port.NewRefreshToken {
	return port.NewRefreshToken{
		UserID:          user.ID,
		TokenHash:       "rot-" + uuid.NewString(),
		ExpiresAt:       time.Now().Add(time.Hour),
		FamilyID:        familyID,
		FamilyStartedAt: time.Now(),
	}
}

// Rotate refuses a successor when the generation moved after the refresh read
// it, even though the old token is still live: the guard is the generation, not
// the revoke.
func TestRotateRefusesAStaleTokenGeneration(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newPasswordUser(t, repos, raceOldPassword)
	family := uuid.NewString()
	old, err := stores.RefreshTokens.Create(ctx, rotationInput(user, family))
	require.NoError(t, err)
	readVersion, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)

	require.NoError(t, stores.Users.BumpTokenVersion(ctx, user.ID))
	err = stores.RefreshTokens.Rotate(ctx, old.ID, rotationInput(user, family), readVersion)

	require.ErrorIs(t, err, port.ErrSessionStale)
	assert.Equal(t, 1, liveRefreshTokens(t, repos, user.ID), "the old token stays and no successor is stored")
}

func TestRotateRefusesADeactivatedAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newPasswordUser(t, repos, raceOldPassword)
	family := uuid.NewString()
	old, err := stores.RefreshTokens.Create(ctx, rotationInput(user, family))
	require.NoError(t, err)
	_, _, err = stores.Users.Deactivate(ctx, user.ID, true)
	require.NoError(t, err)

	// Deactivation bumps the generation as well; use the new one so the
	// deactivation alone is the reason for the refusal.
	readVersion, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)
	err = stores.RefreshTokens.Rotate(ctx, old.ID, rotationInput(user, family), readVersion)

	require.ErrorIs(t, err, port.ErrSessionStale)
	assert.Equal(t, 1, liveRefreshTokens(t, repos, user.ID))
}

func TestRotateSpendsTheOldTokenOnce(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newPasswordUser(t, repos, raceOldPassword)
	family := uuid.NewString()
	old, err := stores.RefreshTokens.Create(ctx, rotationInput(user, family))
	require.NoError(t, err)
	version, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)

	require.NoError(t, stores.RefreshTokens.Rotate(ctx, old.ID, rotationInput(user, family), version))
	err = stores.RefreshTokens.Rotate(ctx, old.ID, rotationInput(user, family), version)

	require.ErrorIs(t, err, port.ErrNotFound)
	assert.Equal(t, 1, liveRefreshTokens(t, repos, user.ID), "the loser stores no second successor")
}

// SetPassword ends the account's sessions in the same transaction.
func TestSetPasswordRevokesTheRefreshTokens(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newPasswordUser(t, repos, raceOldPassword)
	_, err := stores.RefreshTokens.Create(ctx, rotationInput(user, uuid.NewString()))
	require.NoError(t, err)
	_, err = stores.RefreshTokens.Create(ctx, rotationInput(user, uuid.NewString()))
	require.NoError(t, err)

	require.NoError(t, stores.Users.SetPassword(ctx, user.ID, "$2a$10$changed"))

	assert.Zero(t, liveRefreshTokens(t, repos, user.ID))
}

// A thief refreshes first and the owner second with the same token. The second
// use revokes the thief's successor, and signing out with the stale token does
// the same, through the real stores.
func TestSecondUseOfARefreshTokenRevokesTheSuccessor(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	uc := raceUsecases(t, repos)

	for name, secondUse := range map[string]func(token string) error{
		"refresh": func(token string) error { _, err := uc.Refresh(ctx, token); return err },
		"logout":  func(token string) error { return uc.Logout(ctx, token) },
	} {
		t.Run(name, func(t *testing.T) {
			user := newPasswordUser(t, repos, raceOldPassword)
			laptop, err := uc.Login(ctx, user.Email, raceOldPassword)
			require.NoError(t, err)
			phone, err := uc.Login(ctx, user.Email, raceOldPassword)
			require.NoError(t, err)
			thief, err := uc.Refresh(ctx, laptop.RefreshToken)
			require.NoError(t, err)

			_ = secondUse(laptop.RefreshToken)

			_, err = uc.Refresh(ctx, thief.RefreshToken)
			require.Error(t, err, "the thief's successor must not survive the second use")
			_, err = uc.Refresh(ctx, phone.RefreshToken)
			assert.NoError(t, err, "the phone's sign-in is another family")
		})
	}
}
