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
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/server"
)

// The authorization matrix pairs every method and route pattern the API
// router registers with one or more rows of authz_matrix_table_e2e_test.go and
// runs each row for every caller class against its home tenant (X) and a
// foreign tenant (Y). A row states the outcome the product's policy intends,
// taken from openapi.yaml, the use-case guards and deploy/README.md, never the
// outcome the code happens to give. A cell whose outcome differs from policy
// fails; cells already reported as findings are listed in
// authzKnownFindings, which the default run skips and AUTHZ_MATRIX_STRICT=1
// turns back into failures.

// authzCaller is one caller class of the matrix.
type authzCaller string

const (
	callerAnonymous             authzCaller = "C1-anonymous"
	callerKeyRead               authzCaller = "C2-key-read"
	callerKeyIngest             authzCaller = "C3-key-ingest"
	callerKeyAdmin              authzCaller = "C4-key-admin"
	callerNoProject             authzCaller = "C5-no-project"
	callerMember                authzCaller = "C6-member"
	callerManager               authzCaller = "C7-manager"
	callerInstanceAdmin         authzCaller = "C8-instance-admin"
	callerProjectAdmin          authzCaller = "C9-project-admin"
	callerTeamMember            authzCaller = "C10-team-member"
	callerTeamAdmin             authzCaller = "C11-team-admin"
	callerDeactivated           authzCaller = "C12-deactivated"
	callerDemoted               authzCaller = "C13-demoted"
	callerKeyCreatorRemoved     authzCaller = "C14-key-creator-removed"
	callerKeyCreatorDeactivated authzCaller = "C14d-key-creator-deactivated"
	callerRevokedKey            authzCaller = "C15-revoked-key"
	callerExpiredKey            authzCaller = "C16-expired-key"
)

// authzCallers is every caller class in run order.
var authzCallers = []authzCaller{
	callerAnonymous, callerKeyRead, callerKeyIngest, callerKeyAdmin,
	callerNoProject, callerMember, callerManager, callerInstanceAdmin,
	callerProjectAdmin, callerTeamMember, callerTeamAdmin, callerDeactivated,
	callerDemoted, callerKeyCreatorRemoved, callerKeyCreatorDeactivated,
	callerRevokedKey, callerExpiredKey,
}

// deadCredential reports whether the class holds a credential the server must
// refuse outright: none at all, a JWT of a deactivated or re-roled account,
// or a key that is revoked, expired, outlived its creator's access or carries
// the retired admin scope, which key authentication refuses.
func (c authzCaller) deadCredential() bool {
	switch c {
	case callerAnonymous, callerKeyAdmin, callerDeactivated, callerDemoted, callerKeyCreatorRemoved,
		callerKeyCreatorDeactivated, callerRevokedKey, callerExpiredKey:
		return true
	}
	return false
}

// isLiveSession reports whether the class signs in with a working session.
func (c authzCaller) isLiveSession() bool {
	switch c {
	case callerNoProject, callerMember, callerManager, callerInstanceAdmin,
		callerProjectAdmin, callerTeamMember, callerTeamAdmin:
		return true
	}
	return false
}

type authzOutcomeKind int

const (
	kindTodo authzOutcomeKind = iota
	kindAllow
	kindDeny
)

// authzOutcome is what a cell expects. Allow accepts any 2xx (3xx on a
// redirect row) or one of the row's AllowCodes, the validation errors that
// prove the guard let the call through. A denial pins its status code, so a
// 403 that turns into a 404 is drift and fails.
type authzOutcome struct {
	kind authzOutcomeKind
	code int
}

var (
	outcomeTodo    = authzOutcome{kind: kindTodo}
	outcomeAllow   = authzOutcome{kind: kindAllow}
	outcomeDeny401 = authzOutcome{kind: kindDeny, code: http.StatusUnauthorized}
	outcomeDeny403 = authzOutcome{kind: kindDeny, code: http.StatusForbidden}
	outcomeDeny404 = authzOutcome{kind: kindDeny, code: http.StatusNotFound}
)

func (o authzOutcome) String() string {
	switch o.kind {
	case kindAllow:
		return "Allow"
	case kindDeny:
		return fmt.Sprintf("Deny%d", o.code)
	default:
		return "Todo"
	}
}

type authzTenantID string

const (
	authzTenantX authzTenantID = "X"
	authzTenantY authzTenantID = "Y"
)

var (
	bothTenants = []authzTenantID{authzTenantX, authzTenantY}
	onlyX       = []authzTenantID{authzTenantX}
)

// authzAttempt is one cell: a caller against one tenant, plus whatever the
// row prepared for it.
type authzAttempt struct {
	Caller  authzCaller
	Tenant  authzTenantID
	T       *authzTenant
	Token   string
	Obj     map[string]string
	Cookies []*http.Cookie
}

// authzRow is one route pattern (or one variant of it, such as a mixed-tenant
// id pair) with the outcome every caller class should get.
type authzRow struct {
	Method  string
	Pattern string
	// Variant tells rows of one pattern apart; empty for the plain row.
	Variant string
	Path    func(f *authzFixtures, a *authzAttempt) string
	Body    func(f *authzFixtures, a *authzAttempt) any
	// Prepare builds the per-attempt objects (a fresh waiver in the right
	// state, a fresh key, a fresh project) before the call.
	Prepare func(t *testing.T, f *authzFixtures, a *authzAttempt)
	// After runs when the call succeeded, for rows whose success changes a
	// caller credential (a password change).
	After func(t *testing.T, f *authzFixtures, a *authzAttempt, raw []byte)
	// Want is the outcome in the caller's own tenant X. Foreign is the outcome
	// in tenant Y; nil derives it: dead credentials stay Deny401, the instance
	// admin keeps its X outcome, everyone else gets Deny403.
	Want    map[authzCaller]authzOutcome
	Foreign map[authzCaller]authzOutcome
	// Tenants lists the tenants the row runs in; nil means both. Routes with
	// no tenant (the profile, the instance admin area) run once, as X.
	Tenants    []authzTenantID
	AllowCodes []int
	// AllowError is the error code an AllowCodes answer must carry, so a
	// validation refusal is told apart from a missing object.
	AllowError string
	// Audit names what an allowed mutating call must leave behind, comma
	// separated: an audit log event (matched by request id in the server log)
	// or db:<event_type> for a finding or waiver event row.
	Audit string
	// Destructive rows run after every other row, each attempt on objects
	// prepared for it alone.
	Destructive bool
	// FreshSession sends a session caller's call with a freshly signed-in
	// token, for routes that retire the bearer they are given.
	FreshSession bool
	// Redirect rows accept a 3xx as success and do not follow it.
	Redirect bool
}

func (r authzRow) route() string { return r.Method + " " + r.Pattern }

func (r authzRow) tenants() []authzTenantID {
	if r.Tenants == nil {
		return bothTenants
	}
	return r.Tenants
}

// want returns the expected outcome of one cell.
func (r authzRow) want(c authzCaller, tn authzTenantID) authzOutcome {
	if tn == authzTenantX {
		return r.Want[c]
	}
	if r.Foreign != nil {
		return r.Foreign[c]
	}
	own := r.Want[c]
	switch {
	case own == outcomeDeny401:
		return outcomeDeny401
	case c == callerInstanceAdmin:
		return own
	default:
		return outcomeDeny403
	}
}

func (r authzRow) cellKey(c authzCaller, tn authzTenantID) string {
	return strings.Join([]string{r.route(), r.Variant, string(c), string(tn)}, "|")
}

// allowOnly builds a full Want map: the listed callers are allowed, dead
// credentials get Deny401 and every other caller Deny403.
func allowOnly(allowed ...authzCaller) map[authzCaller]authzOutcome {
	out := make(map[authzCaller]authzOutcome, len(authzCallers))
	for _, c := range authzCallers {
		switch {
		case c.deadCredential():
			out[c] = outcomeDeny401
		default:
			out[c] = outcomeDeny403
		}
	}
	for _, c := range allowed {
		out[c] = outcomeAllow
	}
	return out
}

// everyone allows every caller: a public route never reads the bearer.
func everyone() map[authzCaller]authzOutcome {
	out := make(map[authzCaller]authzOutcome, len(authzCallers))
	for _, c := range authzCallers {
		out[c] = outcomeAllow
	}
	return out
}

// with returns a copy of m with the given callers set to o.
func with(m map[authzCaller]authzOutcome, o authzOutcome, callers ...authzCaller) map[authzCaller]authzOutcome {
	out := make(map[authzCaller]authzOutcome, len(m))
	for k, v := range m {
		out[k] = v
	}
	for _, c := range callers {
		out[c] = o
	}
	return out
}

// sameFor applies one outcome to every caller.
func sameFor(o authzOutcome) map[authzCaller]authzOutcome {
	out := make(map[authzCaller]authzOutcome, len(authzCallers))
	for _, c := range authzCallers {
		out[c] = o
	}
	return out
}

// Caller groups the table names over and over.
var (
	// projectSessions are the signed-in people with a role on tenant X.
	projectSessions = []authzCaller{callerMember, callerManager, callerInstanceAdmin, callerProjectAdmin, callerTeamMember}
	// projectReaders adds the read scoped key.
	projectReaders = append([]authzCaller{callerKeyRead}, projectSessions...)
	// managers hold manager rights on tenant X through a session.
	managers = []authzCaller{callerManager, callerInstanceAdmin, callerProjectAdmin}
	// projectWriters are the managers: no key scope covers project management.
	projectWriters = managers
	// projectAdmins hold the project admin role.
	projectAdmins = []authzCaller{callerInstanceAdmin, callerProjectAdmin}
	// sessions are every working signed-in caller, with or without a project.
	sessions = []authzCaller{
		callerNoProject, callerMember, callerManager, callerInstanceAdmin,
		callerProjectAdmin, callerTeamMember, callerTeamAdmin,
	}
)

// authzKnownFinding ties a cell pattern to the finding id it was reported as.
// The pattern is "METHOD PATTERN|variant|caller|tenant|expected", where
// expected is the cell's policy outcome (Allow, Deny401, ...); "*" matches any
// one segment and a pattern of four segments matches every expected outcome.
type authzKnownFinding struct {
	Pattern string
	ID      string
}

// authzKnownFindings lists the cells that fail because the code deviates
// from policy, each reported in the K0 audit report under its id. The first
// matching entry wins. The default run skips a registered cell that still
// fails and fails a registered cell that now passes, so an entry is removed
// when its fix lands. AUTHZ_MATRIX_STRICT=1 ignores the list.
var authzKnownFindings = slices.Concat(
	[]authzKnownFinding{
		// key-outlives-removed-creator: a key keeps working after its creator leaves the project
		// (owner decision).
		{"*|*|C14-key-creator-removed|*|Deny401", "key-outlives-removed-creator"},
		// waiver-update-delete-unaudited: waiver update and delete write no audit line.
		{"PUT /api/v1/projects/{slug}/waivers/{id}||*|*|Allow", "waiver-update-delete-unaudited"},
		{"DELETE /api/v1/projects/{slug}/waivers/{id}||*|*|Allow", "waiver-update-delete-unaudited"},
	},
	// foreign-object-404-vs-403: id-addressed routes that answer 404 where policy pins 403.
	authzCells("GET /api/v1/reports/{id}||%s|*", "foreign-object-404-vs-403", callerNoProject, callerTeamAdmin),
	authzCells("GET /api/v1/reports/{id}||%s|Y", "foreign-object-404-vs-403",
		callerKeyRead, callerMember, callerManager, callerProjectAdmin, callerTeamMember),
	authzCells("POST /api/v1/projects/{slug}/waivers/{id}/approve|x-slug-y-waiver|%s|X", "foreign-object-404-vs-403",
		callerMember, callerTeamMember),
)

// authzCells registers one finding for every value filled into the pattern's
// single %s, a caller class or a route.
func authzCells[V ~string](pattern, id string, values ...V) []authzKnownFinding {
	out := make([]authzKnownFinding, 0, len(values))
	for _, v := range values {
		out = append(out, authzKnownFinding{fmt.Sprintf(pattern, v), id})
	}
	return out
}

// knownFinding returns the finding id registered for a cell, given its key
// and its expected outcome.
func knownFinding(key string, expected authzOutcome) (string, bool) {
	parts := append(strings.Split(key, "|"), expected.String())
	for _, kf := range authzKnownFindings {
		want := strings.Split(kf.Pattern, "|")
		if len(want) == len(parts)-1 {
			want = append(want, "*")
		}
		if len(want) != len(parts) {
			continue
		}
		match := true
		for i := range want {
			if want[i] != "*" && want[i] != parts[i] {
				match = false
				break
			}
		}
		if match {
			return kf.ID, true
		}
	}
	return "", false
}

// walkRouter lists every "METHOD pattern" the API router registers. It builds
// the router in process with nil dependencies: chi.Walk only reads the route
// tree, so no handler or middleware runs.
func walkRouter(t *testing.T) []string {
	t.Helper()
	h := server.NewRouter(server.RouterConfig{OIDCEnabled: true, OIDC: stubOIDC{}})
	routes, ok := h.(chi.Routes)
	require.True(t, ok, "NewRouter returns a chi router")
	var out []string
	require.NoError(t, chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, method+" "+route)
		return nil
	}))
	sort.Strings(out)
	return out
}

// stubOIDC satisfies the router's SSO dependency so the SSO routes are
// registered for the walk.
type stubOIDC struct{}

func (stubOIDC) CallbackHandler(func(context.Context, auth.SSOClaims) (string, error)) http.HandlerFunc {
	return func(http.ResponseWriter, *http.Request) {}
}

func (stubOIDC) LoginURL(string) string { return "/" }

// checkAuthzTable returns every way the table and the router disagree: a
// route with no row, a row whose route is gone, a cell still marked Todo, a
// Want map missing a caller, or two rows with the same route and variant.
func checkAuthzTable(routes []string, rows []authzRow) []string {
	var problems []string
	registered := make(map[string]bool, len(routes))
	for _, r := range routes {
		registered[r] = true
	}
	covered := map[string]bool{}
	seen := map[string]bool{}
	for _, r := range rows {
		id := r.route() + "|" + r.Variant
		if seen[id] {
			problems = append(problems, "duplicate row "+id)
		}
		seen[id] = true
		covered[r.route()] = true
		if !registered[r.route()] {
			problems = append(problems, "row names a route the router does not register: "+id)
		}
		if r.Path == nil {
			problems = append(problems, "row has no Path: "+id)
		}
		for _, tn := range r.tenants() {
			for _, c := range authzCallers {
				var o authzOutcome
				var ok bool
				if tn == authzTenantX || r.Foreign == nil {
					o, ok = r.Want[c]
				} else {
					o, ok = r.Foreign[c]
				}
				if !ok {
					problems = append(problems, fmt.Sprintf("row %s has no outcome for %s in %s", id, c, tn))
					continue
				}
				_ = o
				if r.want(c, tn).kind == kindTodo {
					problems = append(problems, fmt.Sprintf("row %s is Todo for %s in %s", id, c, tn))
				}
			}
		}
	}
	for _, r := range routes {
		if !covered[r] {
			problems = append(problems, "route has no row: "+r)
		}
	}
	sort.Strings(problems)
	return problems
}

// TestAuthzMatrixCompleteness fails when the router and the table drift apart.
func TestAuthzMatrixCompleteness(t *testing.T) {
	routes := walkRouter(t)
	problems := checkAuthzTable(routes, authzRows())
	require.Emptyf(t, problems, "authorization table out of step with the router:\n%s", strings.Join(problems, "\n"))
	t.Logf("%d routes, %d rows, %d callers", len(routes), len(authzRows()), len(authzCallers))
}

// TestAuthzMatrixCompletenessCheck proves the completeness check notices each
// kind of drift, with a stub route list instead of the router.
func TestAuthzMatrixCompletenessCheck(t *testing.T) {
	path := func(*authzFixtures, *authzAttempt) string { return "/" }
	routes := []string{"GET /a", "POST /b"}
	rows := []authzRow{
		{Method: "GET", Pattern: "/a", Path: path, Want: allowOnly()},
		{Method: "PUT", Pattern: "/gone", Path: path, Want: allowOnly()},
		{Method: "GET", Pattern: "/a", Path: path, Want: allowOnly()},
		{Method: "GET", Pattern: "/a", Variant: "todo", Path: path, Want: with(allowOnly(), outcomeTodo, callerMember)},
		{Method: "GET", Pattern: "/a", Variant: "partial", Path: path, Want: map[authzCaller]authzOutcome{callerMember: outcomeAllow}},
	}
	problems := strings.Join(checkAuthzTable(routes, rows), "\n")
	require.Contains(t, problems, "route has no row: POST /b")
	require.Contains(t, problems, "row names a route the router does not register: PUT /gone|")
	require.Contains(t, problems, "duplicate row GET /a|")
	require.Contains(t, problems, "row GET /a|todo is Todo for C6-member in X")
	require.Contains(t, problems, "row GET /a|partial has no outcome for C1-anonymous in X")
	require.Empty(t, checkAuthzTable([]string{"GET /a"}, rows[:1]))

	saved := authzKnownFindings
	defer func() { authzKnownFindings = saved }()
	authzKnownFindings = []authzKnownFinding{
		{"GET /a|*|C6-member|*", "known-test"},
		{"GET /a|*|C7-manager|*|Deny403", "known-deny"},
		{"GET /a|*|C7-manager|*", "known-any"},
	}
	id, ok := knownFinding("GET /a||C6-member|Y", outcomeAllow)
	require.True(t, ok)
	require.Equal(t, "known-test", id)
	id, _ = knownFinding("GET /a||C7-manager|Y", outcomeDeny403)
	require.Equal(t, "known-deny", id, "the first matching entry wins")
	id, _ = knownFinding("GET /a||C7-manager|Y", outcomeAllow)
	require.Equal(t, "known-any", id, "the expected segment narrows a pattern")
	_, ok = knownFinding("GET /a||C8-instance-admin|Y", outcomeAllow)
	require.False(t, ok)
}

// authzResult is one executed cell, for the run summary.
type authzResult struct {
	Key      string `json:"key"`
	Expected string `json:"expected"`
	Status   int    `json:"status"`
	Problem  string `json:"problem,omitempty"`
	Known    string `json:"known,omitempty"`
}

// TestAuthzMatrix runs every row for every caller in both tenants against the
// shared server.
func TestAuthzMatrix(t *testing.T) {
	routes := walkRouter(t)
	rows := authzRows()
	if problems := checkAuthzTable(routes, rows); len(problems) > 0 {
		t.Fatalf("authorization table out of step with the router:\n%s", strings.Join(problems, "\n"))
	}
	f := buildAuthzFixtures(t)
	strict := os.Getenv("AUTHZ_MATRIX_STRICT") == "1"

	var ordered []authzRow
	for _, destructive := range []bool{false, true} {
		for _, r := range rows {
			if r.Destructive == destructive {
				ordered = append(ordered, r)
			}
		}
	}

	var results []authzResult
	start := time.Now()
	for _, r := range ordered {
		for _, c := range authzCallers {
			for _, tn := range r.tenants() {
				key := r.cellKey(c, tn)
				t.Run(key, func(t *testing.T) {
					finished := false
					defer func() {
						// A fixture step that stops the cell still counts in
						// the summary.
						if !finished {
							results = append(results, authzResult{Key: key, Expected: r.want(c, tn).String(), Problem: "cell aborted before its request finished"})
						}
					}()
					res := runAuthzCell(t, f, r, c, tn)
					finished = true
					res.Key = key
					id, registered := knownFinding(key, r.want(c, tn))
					res.Known = id
					results = append(results, res)
					switch {
					case res.Problem != "" && registered && !strict:
						t.Skipf("known finding %s: %s", id, res.Problem)
					case res.Problem != "":
						t.Errorf("%s", res.Problem)
					case registered:
						t.Errorf("cell is registered as finding %s but now matches policy; remove it from authzKnownFindings", id)
					}
				})
			}
		}
	}
	writeAuthzSummary(t, results, time.Since(start))
}

// runAuthzCell executes one cell and returns its result. Problem is empty
// when the outcome, the audit trail and the state check all match policy.
func runAuthzCell(t *testing.T, f *authzFixtures, r authzRow, c authzCaller, tn authzTenantID) authzResult {
	t.Helper()
	expected := r.want(c, tn)
	a := &authzAttempt{Caller: c, Tenant: tn, T: f.tenant(tn), Token: f.callers[c].Token, Obj: map[string]string{}}
	if r.FreshSession {
		a.Token = f.freshSession(t, c)
	}
	if r.Prepare != nil {
		r.Prepare(t, f, a)
	}
	path := r.Path(f, a)
	var body any
	if r.Body != nil {
		body = r.Body(f, a)
	}

	mutating := r.Method != http.MethodGet
	var before string
	if mutating && expected.kind == kindDeny {
		before = f.stateDigest(t)
	}
	var auditChecks []string
	eventsBefore := map[string]int{}
	if mutating && expected.kind == kindAllow && r.Audit != "" {
		auditChecks = strings.Split(r.Audit, ",")
		for _, check := range auditChecks {
			if ev, ok := strings.CutPrefix(check, "db:"); ok {
				eventsBefore[ev] = f.eventCount(t, ev)
			}
		}
	}

	rid := "authz-" + randomHex(12)
	status, raw := authzDo(t, f, r, a, path, body, rid)
	res := authzResult{Expected: expected.String(), Status: status}
	var problems []string

	switch expected.kind {
	case kindAllow:
		ok := status >= 200 && status < 300 || (r.Redirect && status >= 300 && status < 400)
		for _, code := range r.AllowCodes {
			ok = ok || status == code
		}
		if ok && status >= 400 && r.AllowError != "" && !bytes.Contains(raw, []byte(`"code":"`+r.AllowError+`"`)) {
			ok = false
		}
		if !ok {
			problems = append(problems, fmt.Sprintf("expected Allow, got %d: %s", status, clip(raw)))
			break
		}
		if status >= 400 {
			break // a validation answer proves the guard passed but wrote nothing
		}
		if r.After != nil {
			r.After(t, f, a, raw)
		}
		for _, check := range auditChecks {
			if ev, isDB := strings.CutPrefix(check, "db:"); isDB {
				if after := f.eventCount(t, ev); after <= eventsBefore[ev] {
					problems = append(problems, fmt.Sprintf("allowed call recorded no %q finding or waiver event", ev))
				}
				continue
			}
			if !f.audit.waitFor(rid, check, 2*time.Second) {
				problems = append(problems, fmt.Sprintf("allowed call wrote no %q audit line with outcome success (request %s)", check, rid))
			}
		}
	case kindDeny:
		if status != expected.code {
			problems = append(problems, fmt.Sprintf("expected %s, got %d: %s", expected, status, clip(raw)))
		}
		if mutating {
			if after := f.stateDigest(t); after != before {
				problems = append(problems, fmt.Sprintf("denied call (status %d) changed stored state", status))
			}
		}
	default:
		problems = append(problems, "cell is Todo")
	}
	res.Problem = strings.Join(problems, "; ")
	return res
}

// authzXFF hands every request its own client address. The suite trusts
// 127.0.0.1 as a proxy, so this keeps the per-IP buckets on refresh, logout
// and the SSO exchange from turning a matrix of calls into 429s.
var (
	authzXFFMu sync.Mutex
	authzXFFN  int
)

func nextAuthzXFF() string {
	authzXFFMu.Lock()
	defer authzXFFMu.Unlock()
	authzXFFN++
	return fmt.Sprintf("198.18.%d.%d", (authzXFFN/250)%250, authzXFFN%250+1)
}

func authzDo(t *testing.T, f *authzFixtures, r authzRow, a *authzAttempt, path string, body any, rid string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(r.Method, baseURL+path, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	req.Header.Set("X-Request-Id", rid)
	req.Header.Set("X-Forwarded-For", nextAuthzXFF())
	for _, ck := range a.Cookies {
		req.AddCookie(ck)
	}
	client := http.DefaultClient
	if r.Redirect {
		client = noRedirectClient()
	}
	resp, err := client.Do(req)
	require.NoErrorf(t, err, "%s %s", r.Method, path)
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out
}

func clip(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// writeAuthzSummary logs the counts and, when AUTHZ_MATRIX_REPORT names a
// file, writes every cell there as JSON lines for the audit report.
func writeAuthzSummary(t *testing.T, results []authzResult, took time.Duration) {
	t.Helper()
	var failed, known, allowed4xx int
	for _, r := range results {
		switch {
		case r.Problem != "" && r.Known != "":
			known++
		case r.Problem != "":
			failed++
		}
		if r.Problem == "" && r.Expected == "Allow" && r.Status >= 400 {
			allowed4xx++
		}
	}
	t.Logf("authz matrix: %d cells in %s, %d failing, %d known findings, %d allowed with a validation code",
		len(results), took.Round(time.Second), failed, known, allowed4xx)
	path := os.Getenv("AUTHZ_MATRIX_REPORT")
	if path == "" {
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range results {
		require.NoError(t, enc.Encode(r))
	}
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

// authzAuditTail reads the server log incrementally and indexes the audit
// lines by request id.
type authzAuditTail struct {
	path    string
	offset  int64
	partial string
	byID    map[string][]string
}

func newAuthzAuditTail(path string) *authzAuditTail {
	st, err := os.Stat(path)
	var offset int64
	if err == nil {
		offset = st.Size()
	}
	return &authzAuditTail{path: path, offset: offset, byID: map[string][]string{}}
}

var auditRequestID = regexp.MustCompile(`request_id=(\S+)`)

func (a *authzAuditTail) scan() {
	fh, err := os.Open(a.path)
	if err != nil {
		return
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.Seek(a.offset, io.SeekStart); err != nil {
		return
	}
	chunk, err := io.ReadAll(fh)
	if err != nil {
		return
	}
	a.offset += int64(len(chunk))
	text := a.partial + string(chunk)
	lines := strings.Split(text, "\n")
	a.partial = lines[len(lines)-1]
	for _, line := range lines[:len(lines)-1] {
		if !strings.Contains(line, " audit=") {
			continue
		}
		if m := auditRequestID.FindStringSubmatch(line); m != nil {
			a.byID[m[1]] = append(a.byID[m[1]], line)
		}
	}
}

// waitFor reports whether the request wrote a successful audit line for event.
func (a *authzAuditTail) waitFor(rid, event string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		a.scan()
		for _, line := range a.byID[rid] {
			if strings.Contains(line, " audit="+event+" ") && strings.Contains(line, " outcome=success") {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestAuthzMatrixFirstRunSetup covers the routes whose authorization depends
// on an empty database, on a server of its own: POST /api/v1/setup, and the
// SSO routes, which a server without SSO_ENABLE must not register at all. The
// SSO rows of the main matrix run against the shared server's fake IdP.
func TestAuthzMatrixFirstRunSetup(t *testing.T) {
	const token = "authz-matrix-setup-token-0001"
	srv := startFreshServer(t, "specht_authz_setup", "SETUP_TOKEN="+token)
	conn, err := pgx.Connect(context.Background(), strings.Replace(dsn, "/specht_e2e?", "/specht_authz_setup?", 1))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	// Migration 21 seeds a system account on every install; like CountUsers,
	// count the people.
	users := func() int {
		var n int
		require.NoError(t, conn.QueryRow(context.Background(),
			"SELECT count(*) FROM users WHERE email <> 'system@specht.local'").Scan(&n))
		return n
	}
	account := func(label string) map[string]any {
		return map[string]any{"email": "authz-setup-" + label + "@example.com", "password": "Az-" + randomHex(12)}
	}

	// No account exists, so the only callers are anonymous ones and ones
	// sending a bearer no server ever issued; setup never reads the bearer.
	for _, bearer := range []string{"", "vuln_" + randomHex(20), "not-a-jwt"} {
		status, _, raw := srv.do(t, http.MethodPost, "/api/v1/setup", bearer, merge(account("bad"), "token", "authz-wrong-token-0000"))
		require.Equalf(t, http.StatusForbidden, status, "wrong token with bearer %q: %s", bearer, raw)
		require.Contains(t, string(raw), `"code":"invalid_setup_token"`)
		require.Zero(t, users(), "a refused setup creates no account")
	}
	status, _, raw := srv.do(t, http.MethodGet, "/api/v1/projects", "", nil)
	require.Equalf(t, http.StatusUnauthorized, status, "a pending setup opens no other route: %s", raw)

	// The good token from several requests at once creates one account.
	const racers = 8
	codes := make(chan int, racers)
	var wg sync.WaitGroup
	for i := range racers {
		raw, err := json.Marshal(merge(account(fmt.Sprint(i)), "token", token))
		require.NoError(t, err)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(srv.url+"/api/v1/setup", "application/json", bytes.NewReader(raw))
			if err != nil {
				codes <- 0
				return
			}
			_ = resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	created := 0
	for code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusNotFound:
		default:
			t.Errorf("concurrent setup answered %d, want 201 or 404", code)
		}
	}
	require.Equal(t, 1, created, "exactly one concurrent setup succeeds")
	require.Equal(t, 1, users(), "exactly one account exists after setup")
	require.Eventually(t, func() bool {
		return strings.Contains(srv.readLog(), "audit=setup.complete outcome=success")
	}, 2*time.Second, 50*time.Millisecond, "setup writes its audit line")

	// The door is closed for every caller, the right token included.
	for _, tok := range []string{token, "authz-wrong-token-0000"} {
		status, _, raw = srv.do(t, http.MethodPost, "/api/v1/setup", "", merge(account("late"), "token", tok))
		require.Equalf(t, http.StatusNotFound, status, "setup after the first account: %s", raw)
	}
	require.Equal(t, 1, users())

	for _, path := range []string{"/api/v1/auth/sso/login", "/api/v1/auth/sso/callback?code=x&state=y"} {
		status, _, raw = srv.do(t, http.MethodGet, path, "", nil)
		require.Equalf(t, http.StatusNotFound, status, "%s without SSO: %s", path, raw)
	}
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/auth/sso/exchange", "", map[string]string{"code": "authz"})
	require.NotEqualf(t, http.StatusOK, status, "an SSO exchange without SSO signs nobody in: %s", raw)
}
