//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// registerPerson makes a fresh account, so a test can change or switch one off without
// touching the shared viewer.
func registerPerson(t *testing.T, label string) authResponse {
	t.Helper()
	return request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": label + "-" + randomHex(4) + "@example.com", "password": adminPass}, http.StatusCreated)
}

// TestE2E_CLIRunsAProjectFromCreationToDeletion walks an admin who sets up a project, gives a
// teammate access, makes a key for CI, and later tears the project down.
func TestE2E_CLIRunsAProjectFromCreationToDeletion(t *testing.T) {
	slug := "cli-life-" + randomHex(3)
	person := registerPerson(t, "teammate")

	stdout, stderr, exit := cli(t, "projects", "create", "--name", "CLI Life", "--slug", slug, "--description", "made in a test")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, slug)

	_, stderr, exit = cli(t, "projects", "create", "--name", "Again", "--slug", slug)
	require.NotZero(t, exit, "a second project cannot take the same slug")
	require.NotEmpty(t, stderr)

	stdout, stderr, exit = cli(t, "projects", "update", slug, "--name", "CLI Life Renamed")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "CLI Life Renamed")

	_, stderr, exit = cli(t, "projects", "update", slug)
	require.Equal(t, 2, exit, "an update with nothing to change is a usage error")
	require.Contains(t, stderr, "nothing to change")

	// Access: by email, then the role changes, then it goes away.
	stdout, stderr, exit = cli(t, "members", "add", "--project", slug, "--email", person.Email, "--role", "member")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, person.Email)

	_, stderr, exit = cli(t, "members", "add", "--project", slug, "--user", person.UserID, "--email", person.Email, "--role", "member")
	require.Equal(t, 2, exit, "naming the person twice is a usage error")
	require.Contains(t, stderr, "only one")

	_, stderr, exit = cli(t, "members", "add", "--project", slug, "--email", "nobody-"+randomHex(4)+"@example.com", "--role", "member")
	require.NotZero(t, exit, "an address with no account is refused")
	require.NotEmpty(t, stderr)

	stdout, stderr, exit = cli(t, "members", "add", "--project", slug, "--user", person.UserID, "--role", "manager")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "manager", "adding again changes the role")

	stdout, stderr, exit = cli(t, "members", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, person.Email)
	require.Contains(t, stdout, "manager")

	stdout, stderr, exit = cli(t, "members", "remove", "--project", slug, "--user", person.UserID)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "member removed")

	stdout, stderr, exit = cli(t, "members", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.NotContains(t, stdout, person.Email)

	// A key for CI: shown once, listed by prefix, then revoked.
	stdout, stderr, exit = cli(t, "--format", "json", "api-keys", "create", "--project", slug, "--name", "ci")
	require.Zero(t, exit, stderr)
	keyID := firstJSONField(t, "["+stdout+"]", "id")
	rawKey := firstJSONField(t, "["+stdout+"]", "raw_key")
	require.NotEmpty(t, rawKey)

	stdout, stderr, exit = cli(t, "api-keys", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, keyID)
	require.Contains(t, stdout, "ci")
	require.NotContains(t, stdout, rawKey, "the list never shows the key itself")

	stdout, stderr, exit = runBin(t, cliBin, []string{"API_URL=" + baseURL, "API_KEY=" + rawKey}, "findings", "list", "--project", slug)
	require.Zero(t, exit, stderr+stdout)

	stdout, stderr, exit = cli(t, "api-keys", "revoke", "--project", slug, "--id", keyID)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "key revoked")

	_, _, exit = runBin(t, cliBin, []string{"API_URL=" + baseURL, "API_KEY=" + rawKey}, "findings", "list", "--project", slug)
	require.NotZero(t, exit, "a revoked key stops working")

	// Tear down: the confirmation is required.
	_, stderr, exit = cli(t, "projects", "delete", slug)
	require.Equal(t, 2, exit)
	require.Contains(t, stderr, "--yes")

	stdout, stderr, exit = cli(t, "projects", "delete", slug, "--yes")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "deleted")

	_, _, exit = cli(t, "projects", "get", slug)
	require.NotZero(t, exit, "the project is gone")
}

// TestE2E_CLIAdministersAccounts walks an admin who promotes a person, locks them out, helps them
// back in with a link, and lets them sign in again.
func TestE2E_CLIAdministersAccounts(t *testing.T) {
	person := registerPerson(t, "account")

	stdout, stderr, exit := cli(t, "users", "list", "--email", person.Email)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, person.UserID)
	require.Contains(t, stdout, "member")
	require.Contains(t, stdout, "active")

	stdout, stderr, exit = cli(t, "users", "role", "--id", person.UserID, "--role", "admin")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "admin")

	_, stderr, exit = cli(t, "users", "role", "--id", person.UserID, "--role", "owner")
	require.NotZero(t, exit, "a role outside the vocabulary is refused")
	require.NotEmpty(t, stderr)

	stdout, stderr, exit = cli(t, "users", "role", "--id", person.UserID, "--role", "member")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "member")

	stdout, stderr, exit = cli(t, "users", "deactivate", "--id", person.UserID)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "deactivated")

	status, _ := doJSON(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"email": person.Email, "password": adminPass})
	require.NotEqual(t, http.StatusOK, status, "a deactivated account cannot sign in")

	stdout, stderr, exit = cli(t, "users", "reactivate", "--id", person.UserID)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "active")
	login(t, person.Email, adminPass)

	stdout, stderr, exit = cli(t, "--format", "json", "users", "reset-link", "--id", person.UserID)
	require.Zero(t, exit, stderr)
	require.NotEmpty(t, firstJSONField(t, "["+stdout+"]", "link"))

	// A project key is not a session, so account administration refuses it.
	slug := newProject(t, "cli-users-key")
	_, stderr, exit = runBin(t, cliBin, []string{"API_URL=" + baseURL, "API_KEY=" + mintKey(t, slug)}, "users", "list")
	require.NotZero(t, exit)
	require.NotEmpty(t, stderr)
}

// TestE2E_CLIManagesInviteLinks makes a link, finds it in the list, and revokes it.
func TestE2E_CLIManagesInviteLinks(t *testing.T) {
	slug := newProject(t, "cli-invites")

	stdout, stderr, exit := cli(t, "invites", "create", "--project", slug, "--role", "member", "--days", "3")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "/invite/")
	require.Contains(t, stdout, "shown once")

	_, stderr, exit = cli(t, "invites", "create", "--project", slug, "--role", "member", "--days", "31")
	require.NotZero(t, exit, "a link lasts at most 30 days")
	require.NotEmpty(t, stderr)

	stdout, stderr, exit = cli(t, "--format", "json", "invites", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	inviteID := firstJSONField(t, stdout, "id")
	require.NotEmpty(t, inviteID)

	stdout, stderr, exit = cli(t, "invites", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, inviteID)
	require.Contains(t, stdout, "anyone", "a link with no address can be taken by whoever opens it")

	stdout, stderr, exit = cli(t, "invites", "revoke", "--project", slug, "--id", inviteID)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "invite revoked")

	stdout, stderr, exit = cli(t, "invites", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "No open invites.")

	_, stderr, exit = runBin(t, cliBin, []string{"API_URL=" + baseURL, "API_KEY=" + mintKey(t, slug)}, "invites", "list", "--project", slug)
	require.NotZero(t, exit, "invite links need a signed-in session")
	require.NotEmpty(t, stderr)
}
