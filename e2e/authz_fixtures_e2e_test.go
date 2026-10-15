//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// The authorization matrix runs against two tenants. Tenant X is the home of
// every caller class; tenant Y is a foreign project with the same objects, so a
// row can ask whether X's callers reach Y. Scratch project Z holds single-use
// invites, which change the membership of whoever redeems them.

// authzPrincipal is one credential the matrix sends: a session JWT or a
// project API key.
type authzPrincipal struct {
	Email    string
	Password string
	UserID   string
	Token    string
	KeyID    string
}

// authzTenant is one project with one of every object a route can address.
type authzTenant struct {
	Name      authzTenantID
	Slug      string
	ProjectID string
	// IngestKey is a project key minted by the suite admin for fixture ingests.
	IngestKey  string
	ReportID   string
	FindingID  string
	Finding2ID string
	WaiverID   string
	// InviteToken is a pending member invite of this project.
	InviteToken string
	EvidenceID  string
	EnvID       string
	// TeamLinked is linked to the project with the member role; TeamOwned has
	// no project link and its admin is C11 in tenant X; TeamLinkTarget is
	// what the link route relinks.
	TeamLinked     string
	TeamOwned      string
	TeamLinkTarget string
	// Requester is a direct project member who files the waiver requests
	// that the approve, reject and withdraw rows decide on.
	Requester *authzPrincipal
}

// authzFixtures is everything the matrix rows read.
type authzFixtures struct {
	X, Y *authzTenant
	// ZSlug is the scratch project that accept and join invites point at.
	ZSlug        string
	callers      map[authzCaller]*authzPrincipal
	spare        *authzPrincipal
	templateID   string
	templateName string
	db           *pgx.Conn
	audit        *authzAuditTail
	seq          atomic.Int64
}

// authzCommit is the commit every fixture report carries, in both tenants, so
// a pull-request check against tenant X finds X's report for it and a
// foreign report id is the only thing that differs.
const authzCommit = "a11cafe0a11cafe0a11cafe0a11cafe0a11cafe0"

func (f *authzFixtures) tenant(id authzTenantID) *authzTenant {
	if id == authzTenantY {
		return f.Y
	}
	return f.X
}

// unique returns a short label no other attempt in this run uses.
func (f *authzFixtures) unique(label string) string {
	return fmt.Sprintf("authz-%s-%d-%s", label, f.seq.Add(1), randomHex(3))
}

// nextCommit returns a fresh 40-hex commit so a re-ingest is a new report and
// never a replay.
func (f *authzFixtures) nextCommit() string {
	return fmt.Sprintf("%040x", 0xa0000000+f.seq.Add(1))
}

func buildAuthzFixtures(t *testing.T) *authzFixtures {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	f := &authzFixtures{
		callers: map[authzCaller]*authzPrincipal{},
		db:      conn,
		audit:   newAuthzAuditTail(serverLog.Name()),
	}
	f.spare = azRegister(t, "spare")
	f.templateName = f.unique("template")
	tpl := request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/policy-templates", adminToken, map[string]any{
		"name": f.templateName, "description": "authz matrix",
		"definition": map[string]string{"severity_floor": "high"},
	}, http.StatusCreated)
	f.templateID = tpl.ID

	f.X = buildAuthzTenant(t, f, authzTenantX)
	f.Y = buildAuthzTenant(t, f, authzTenantY)
	f.ZSlug = newProject(t, "authz-z")
	azWatcherOff(t, f.ZSlug)
	buildAuthzCallers(t, f)
	return f
}

func buildAuthzTenant(t *testing.T, f *authzFixtures, id authzTenantID) *authzTenant {
	t.Helper()
	slug := newProject(t, "authz-"+strings.ToLower(string(id)))
	tn := &authzTenant{Name: id, Slug: slug}
	project := request[projectResponse](t, http.MethodGet, "/api/v1/projects/"+slug, adminToken, nil, http.StatusOK)
	tn.ProjectID = project.ID
	azWatcherOff(t, slug)

	tn.IngestKey = mintKey(t, slug)
	ingest := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", tn.IngestKey,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
			"commit_sha": authzCommit, "branch": "main", "environment": "authz-prod",
		}), http.StatusCreated)
	tn.ReportID = ingest.ReportID
	high := highFinding(t, slug)
	tn.FindingID = high.ID
	for _, fd := range listFindings(t, slug) {
		if fd.ID != high.ID {
			tn.Finding2ID = fd.ID
			break
		}
	}
	require.NotEmpty(t, tn.Finding2ID, "the fixture report needs a second finding")

	tn.WaiverID = createWaiver(t, slug, f.unique("waiver"), tn.FindingID, "").ID
	tn.InviteToken = azInvite(t, slug)
	tn.EvidenceID = azEvidence(t, tn.FindingID)
	request[map[string]any](t, http.MethodPost, "/api/v1/findings/"+tn.FindingID+"/signoff", adminToken,
		map[string]string{"status": "pending", "comment": "authz fixture"}, http.StatusOK)

	envs := request[[]struct {
		ID string `json:"id"`
	}](t, http.MethodGet, "/api/v1/projects/"+slug+"/environments", adminToken, nil, http.StatusOK)
	require.NotEmpty(t, envs, "the fixture ingest names an environment")
	tn.EnvID = envs[0].ID

	tn.TeamLinked = azTeam(t, f)
	tn.TeamOwned = azTeam(t, f)
	tn.TeamLinkTarget = azTeam(t, f)
	azLinkTeam(t, slug, tn.TeamLinked)

	tn.Requester = azRegister(t, "requester-"+strings.ToLower(string(id)))
	azAddMember(t, slug, tn.Requester.UserID, "member")
	return tn
}

// buildAuthzCallers creates the sixteen caller classes, all homed
// in tenant X. C14 has two forms: the creator removed from the project, and
// the creator deactivated.
func buildAuthzCallers(t *testing.T, f *authzFixtures) {
	t.Helper()
	x := f.X
	set := func(c authzCaller, p *authzPrincipal) { f.callers[c] = p }

	set(callerAnonymous, &authzPrincipal{})
	set(callerKeyRead, azScopedKey(t, f, x.Slug, `["read"]`))
	set(callerKeyIngest, azScopedKey(t, f, x.Slug, `["ingest"]`))
	set(callerKeyAdmin, azScopedKey(t, f, x.Slug, `["admin"]`))
	set(callerNoProject, azRegister(t, "c5"))

	member := azRegister(t, "c6")
	azAddMember(t, x.Slug, member.UserID, "member")
	set(callerMember, member)

	manager := azRegister(t, "c7")
	azAddMember(t, x.Slug, manager.UserID, "manager")
	set(callerManager, manager)

	instAdmin := azRegister(t, "c8")
	azSetGlobalRole(t, instAdmin.UserID, "admin")
	instAdmin.Token = azLogin(t, instAdmin)
	set(callerInstanceAdmin, instAdmin)

	projAdmin := azRegister(t, "c9")
	azAddMember(t, x.Slug, projAdmin.UserID, "admin")
	set(callerProjectAdmin, projAdmin)

	teamMember := azRegister(t, "c10")
	azAddTeamMember(t, x.TeamLinked, teamMember.UserID, "member")
	set(callerTeamMember, teamMember)

	teamAdmin := azRegister(t, "c11")
	azAddTeamMember(t, x.TeamOwned, teamAdmin.UserID, "admin")
	set(callerTeamAdmin, teamAdmin)

	deactivated := azRegister(t, "c12")
	azAddMember(t, x.Slug, deactivated.UserID, "admin")
	deactivated.Token = azLogin(t, deactivated)
	azSetActive(t, deactivated.UserID, false)
	set(callerDeactivated, deactivated)

	demoted := azRegister(t, "c13")
	azSetGlobalRole(t, demoted.UserID, "admin")
	demoted.Token = azLogin(t, demoted)
	azSetGlobalRole(t, demoted.UserID, "member")
	set(callerDemoted, demoted)

	removedCreator := azRegister(t, "c14")
	azAddMember(t, x.Slug, removedCreator.UserID, "manager")
	set(callerKeyCreatorRemoved, azKeyBy(t, removedCreator.Token, x.Slug))
	status, raw := doJSON(t, http.MethodDelete, "/api/v1/projects/"+x.Slug+"/members/"+removedCreator.UserID, adminToken, nil)
	require.Equalf(t, http.StatusNoContent, status, "remove c14 creator: %s", raw)

	deactivatedCreator := azRegister(t, "c14d")
	azAddMember(t, x.Slug, deactivatedCreator.UserID, "manager")
	set(callerKeyCreatorDeactivated, azKeyBy(t, deactivatedCreator.Token, x.Slug))
	azSetActive(t, deactivatedCreator.UserID, false)

	revoked := azScopedKey(t, f, x.Slug, `["ingest","read"]`)
	status, raw = doJSON(t, http.MethodDelete, "/api/v1/auth/apikeys/"+revoked.KeyID+"?project="+x.Slug, adminToken, nil)
	require.Equalf(t, http.StatusNoContent, status, "revoke c15 key: %s", raw)
	set(callerRevokedKey, revoked)

	expired := azScopedKey(t, f, x.Slug, `["ingest","read"]`)
	_, err := f.db.Exec(context.Background(),
		"UPDATE api_keys SET expires_at = now() - interval '1 hour' WHERE id = $1", expired.KeyID)
	require.NoError(t, err)
	set(callerExpiredKey, expired)

	for _, c := range authzCallers {
		require.Containsf(t, f.callers, c, "fixture for caller %s", c)
	}
}

// freshSession signs a session caller in again, for rows whose call retires
// the bearer token it was sent with. Other callers keep their credential.
func (f *authzFixtures) freshSession(t *testing.T, c authzCaller) string {
	t.Helper()
	p := f.callers[c]
	if !c.isLiveSession() {
		return p.Token
	}
	return azLogin(t, p)
}

// grantHome gives caller c in a freshly created project the same standing it
// has in tenant X, so a destructive row can spend that project. It returns
// the token the attempt must send.
func (f *authzFixtures) grantHome(t *testing.T, c authzCaller, slug string) string {
	t.Helper()
	p := f.callers[c]
	switch c {
	case callerMember:
		azAddMember(t, slug, p.UserID, "member")
	case callerManager:
		azAddMember(t, slug, p.UserID, "manager")
	case callerProjectAdmin:
		azAddMember(t, slug, p.UserID, "admin")
	case callerTeamMember:
		azLinkTeam(t, slug, f.X.TeamLinked)
	case callerKeyRead:
		return azScopedKey(t, f, slug, `["read"]`).Token
	case callerKeyIngest:
		return azScopedKey(t, f, slug, `["ingest"]`).Token
	case callerKeyAdmin:
		return azScopedKey(t, f, slug, `["admin"]`).Token
	}
	return p.Token
}

func azRegister(t *testing.T, label string) *authzPrincipal {
	t.Helper()
	p := &authzPrincipal{
		Email:    fmt.Sprintf("authz-%s-%s@example.com", label, randomHex(4)),
		Password: "Az-" + randomHex(12),
	}
	resp := azPublicPost(t, "/api/v1/auth/register", map[string]string{"email": p.Email, "password": p.Password}, http.StatusCreated)
	require.NotEmpty(t, resp.Token)
	p.UserID, p.Token = resp.UserID, resp.Token
	return p
}

func azLogin(t *testing.T, p *authzPrincipal) string {
	t.Helper()
	resp := azSignIn(t, p)
	require.NotEmpty(t, resp.Token)
	return resp.Token
}

// azSignIn signs a person in.
func azSignIn(t *testing.T, p *authzPrincipal) authResponse {
	t.Helper()
	return azPublicPost(t, "/api/v1/auth/login", map[string]string{"email": p.Email, "password": p.Password}, http.StatusOK)
}

// azPublicPost sends a sign-in or sign-up from a client address of its own.
// The matrix registers and signs in hundreds of times, which a single
// address would spend from the per-IP login bucket until the server answers
// 429.
func azPublicPost(t *testing.T, path string, body any, want int) authResponse {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", nextAuthzXFF())
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equalf(t, want, resp.StatusCode, "POST %s: %s", path, out)
	var auth authResponse
	require.NoError(t, json.Unmarshal(out, &auth))
	return auth
}

func azAddMember(t *testing.T, slug, userID, role string) {
	t.Helper()
	request[map[string]any](t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
		map[string]string{"user_id": userID, "role": role}, http.StatusCreated)
}

func azSetGlobalRole(t *testing.T, userID, role string) {
	t.Helper()
	request[map[string]any](t, http.MethodPut, "/api/v1/users/"+userID+"/role", adminToken,
		map[string]string{"role": role}, http.StatusOK)
}

func azSetActive(t *testing.T, userID string, active bool) {
	t.Helper()
	action := "deactivate"
	if active {
		action = "reactivate"
	}
	request[map[string]any](t, http.MethodPost, "/api/v1/users/"+userID+"/"+action, adminToken, nil, http.StatusOK)
}

func azTeam(t *testing.T, f *authzFixtures) string {
	t.Helper()
	team := request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/teams", adminToken,
		map[string]string{"name": f.unique("team")}, http.StatusCreated)
	return team.ID
}

func azAddTeamMember(t *testing.T, teamID, userID, role string) {
	t.Helper()
	request[map[string]any](t, http.MethodPost, "/api/v1/teams/"+teamID+"/members", adminToken,
		map[string]string{"user_id": userID, "role": role}, http.StatusCreated)
}

func azLinkTeam(t *testing.T, slug, teamID string) {
	t.Helper()
	request[map[string]any](t, http.MethodPost, "/api/v1/projects/"+slug+"/teams", adminToken,
		map[string]string{"team_id": teamID, "role": "member"}, http.StatusCreated)
}

// azWatcherOff stops the CVE watcher daemon from polling a matrix project, so
// nothing but the matrix writes to its rows while a cell runs.
func azWatcherOff(t *testing.T, slug string) {
	t.Helper()
	request[map[string]any](t, http.MethodPut, "/api/v1/projects/"+slug+"/watcher", adminToken,
		map[string]any{"enabled": false}, http.StatusOK)
}

// azInvite creates a pending member invite and returns its token.
func azInvite(t *testing.T, slug string) string {
	t.Helper()
	inv := request[struct {
		Link string `json:"link"`
	}](t, http.MethodPost, "/api/v1/projects/"+slug+"/invites", adminToken,
		map[string]string{"role": "member"}, http.StatusCreated)
	token := strings.TrimPrefix(inv.Link, "/invite/")
	require.NotEqual(t, inv.Link, token, "invite link shape: %s", inv.Link)
	return token
}

// azInviteID creates a pending member invite and returns its id.
func azInviteID(t *testing.T, slug string) string {
	t.Helper()
	inv := request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/projects/"+slug+"/invites", adminToken,
		map[string]string{"role": "member"}, http.StatusCreated)
	return inv.ID
}

func azEvidence(t *testing.T, findingID string) string {
	t.Helper()
	ev := request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/findings/"+findingID+"/evidence", adminToken, map[string]string{
		"type": "reference", "url": "https://example.com/authz", "description": "authz fixture",
	}, http.StatusCreated)
	return ev.ID
}

// azScopedKey mints a key with the suite admin and rewrites its scopes in the
// database: the API only mints ["ingest","read"], so the read-only,
// ingest-only and admin-scope classes exist only this way.
func azScopedKey(t *testing.T, f *authzFixtures, slug, scopes string) *authzPrincipal {
	t.Helper()
	resp := request[apiKeyResponse](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
		map[string]string{"project": slug, "name": f.unique("key")}, http.StatusCreated)
	_, err := f.db.Exec(context.Background(), "UPDATE api_keys SET scopes = $1::jsonb WHERE id = $2", scopes, resp.ID)
	require.NoError(t, err)
	return &authzPrincipal{Token: resp.RawKey, KeyID: resp.ID}
}

// azKeyBy mints a key with the given session, so the key's creator is that
// person.
func azKeyBy(t *testing.T, token, slug string) *authzPrincipal {
	t.Helper()
	resp := request[apiKeyResponse](t, http.MethodPost, "/api/v1/auth/apikeys", token,
		map[string]string{"project": slug, "name": "authz-" + randomHex(3)}, http.StatusCreated)
	return &authzPrincipal{Token: resp.RawKey, KeyID: resp.ID}
}

// azFreshReport ingests the fixture again under a new commit and returns the
// new report id.
func (f *authzFixtures) azFreshReport(t *testing.T, tn *authzTenant) string {
	t.Helper()
	resp := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", tn.IngestKey,
		ingestBodyWith(t, tn.Slug, "high-medium.sarif.json", map[string]any{
			"commit_sha": f.nextCommit(), "branch": "authz-scratch",
		}), http.StatusCreated)
	return resp.ReportID
}

// clearPendingRequests withdraws every pending waiver request of a tenant in
// the database, so the next request for the same finding is not a duplicate.
func (f *authzFixtures) clearPendingRequests(t *testing.T, tn *authzTenant) {
	t.Helper()
	_, err := f.db.Exec(context.Background(),
		"UPDATE waivers SET status = 'withdrawn' WHERE project_id = $1 AND status = 'pending'", tn.ProjectID)
	require.NoError(t, err)
}

// pendingRequest files a fresh waiver request by the tenant's requester and
// returns its id.
func (f *authzFixtures) pendingRequest(t *testing.T, tn *authzTenant) string {
	t.Helper()
	f.clearPendingRequests(t, tn)
	requester := tn.Requester
	if tn.Name == authzTenantX {
		requester = f.callers[callerMember]
	}
	w := request[waiverDetail](t, http.MethodPost, "/api/v1/projects/"+tn.Slug+"/waivers/requests", requester.Token,
		map[string]any{
			"target_ids": []string{tn.FindingID},
			"reason":     "authz matrix request",
			"expires_at": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		}, http.StatusCreated)
	return w.ID
}

// otherAnalysisState returns an analysis state the finding is not in, so a
// triage call is a real change that records an event.
func (f *authzFixtures) otherAnalysisState(t *testing.T, findingID string) string {
	t.Helper()
	var state *string
	require.NoError(t, f.db.QueryRow(context.Background(),
		"SELECT analysis_state FROM findings WHERE id = $1", findingID).Scan(&state))
	if state != nil && *state == "in_triage" {
		return "exploitable"
	}
	return "in_triage"
}

// latestAnalysisEvent returns the newest analysis_changed event of a finding.
func (f *authzFixtures) latestAnalysisEvent(t *testing.T, findingID string) string {
	t.Helper()
	var id string
	require.NoError(t, f.db.QueryRow(context.Background(),
		`SELECT id FROM finding_events WHERE finding_id = $1 AND event_type = 'analysis_changed'
		 ORDER BY created_at DESC, id DESC LIMIT 1`, findingID).Scan(&id))
	return id
}

// azResetToken issues a password reset link for a user and returns its token.
func azResetToken(t *testing.T, userID string) string {
	t.Helper()
	link := request[struct {
		Link string `json:"link"`
	}](t, http.MethodPost, "/api/v1/users/"+userID+"/reset-link", adminToken, nil, http.StatusCreated)
	token := strings.TrimPrefix(link.Link, "/reset/")
	require.NotEqual(t, link.Link, token, "reset link shape: %s", link.Link)
	return token
}

// azRefreshToken signs a throwaway person in and returns the refresh token.
func azRefreshToken(t *testing.T, p *authzPrincipal) string {
	t.Helper()
	resp := azSignIn(t, p)
	require.NotEmpty(t, resp.RefreshToken)
	return resp.RefreshToken
}

// stateDigest hashes every table a denied call could touch. Columns that
// change on reads (API key last use) are left out.
const authzStateDigestSQL = `
SELECT md5(string_agg(n || ':' || h, ',' ORDER BY n)) FROM (
  SELECT 'projects' n, md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) h FROM projects t
  UNION ALL SELECT 'project_members', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), '')) FROM project_members t
  UNION ALL SELECT 'teams', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM teams t
  UNION ALL SELECT 'team_members', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), '')) FROM team_members t
  UNION ALL SELECT 'project_teams', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), '')) FROM project_teams t
  UNION ALL SELECT 'api_keys', md5(coalesce(string_agg((to_jsonb(t) - 'last_used_at')::text, '|' ORDER BY t.id), '')) FROM api_keys t
  UNION ALL SELECT 'invites', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM invites t
  UNION ALL SELECT 'findings', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM findings t
  UNION ALL SELECT 'finding_events', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM finding_events t
  UNION ALL SELECT 'waivers', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM waivers t
  UNION ALL SELECT 'waiver_events', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM waiver_events t
  UNION ALL SELECT 'waiver_finding_targets', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), '')) FROM waiver_finding_targets t
  UNION ALL SELECT 'evidence_artifacts', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM evidence_artifacts t
  UNION ALL SELECT 'reachability_assessments', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM reachability_assessments t
  UNION ALL SELECT 'signoffs', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), '')) FROM signoffs t
  UNION ALL SELECT 'environments', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM environments t
  UNION ALL SELECT 'policy_templates', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM policy_templates t
  UNION ALL SELECT 'reports', md5(coalesce(string_agg((to_jsonb(t) - 'raw_data')::text, '|' ORDER BY t.id), '')) FROM reports t
  UNION ALL SELECT 'users', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY t.id), '')) FROM users t
  UNION ALL SELECT 'password_resets', md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), '')) FROM password_resets t
) s`

func (f *authzFixtures) stateDigest(t *testing.T) string {
	t.Helper()
	var digest string
	require.NoError(t, f.db.QueryRow(context.Background(), authzStateDigestSQL).Scan(&digest))
	return digest
}

// eventCount counts the finding and waiver events of one type.
func (f *authzFixtures) eventCount(t *testing.T, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, f.db.QueryRow(context.Background(), `
SELECT (SELECT count(*) FROM finding_events WHERE event_type = $1)
     + (SELECT count(*) FROM waiver_events WHERE event_type = $1)`, eventType).Scan(&n))
	return n
}

// ingestBody builds an ingest payload without a *testing.T, for table rows.
func (f *authzFixtures) ingestBody(slug, commit, branch string) map[string]any {
	raw, err := os.ReadFile(filepath.Join("testdata", "high-medium.sarif.json"))
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"project": slug, "scanner": "sarif", "raw_data": json.RawMessage(raw),
		"commit_sha": commit, "branch": branch,
	}
}
