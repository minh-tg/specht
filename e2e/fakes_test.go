//go:build e2e

package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Test-time service fakes, started in runE2E before the server so every
// wired endpoint (SSO IdP, OSV feed, webhook sinks) exists at boot:
//
//   - fakeIdP:   SSO_ISSUER_URL target — JWKS, authorize, token, userinfo
//   - fakeOSV:   WATCHER_OSV_ENDPOINT — empty querybatch answers by default
//   - webhooks:  WATCHER_WEBHOOK_URL(S) — capture tracker/notify deliveries
//
// The smoke suite (service_fakes_e2e_test.go) proves each wire end to end;
// the watcher, tracker, and SSO business processes build on them.

const (
	e2eIdPClientID     = "e2e-client"
	e2eIdPClientSecret = "e2e-secret"
	e2eWebhookSecret   = "e2e-signing-secret"
	e2eSSOEmail        = "e2e-sso@example.com"
)

type capturedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// captureSink records every webhook delivery for assertions.
type captureSink struct {
	mu   sync.Mutex
	reqs []capturedRequest
	srv  *httptest.Server
}

func newCaptureSink() *captureSink {
	s := &captureSink{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, capturedRequest{
			Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body,
		})
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	return s
}

func (s *captureSink) URL() string { return s.srv.URL }

func (s *captureSink) snapshot() []capturedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]capturedRequest, len(s.reqs))
	copy(out, s.reqs)
	return out
}

func (s *captureSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

// fakeOSV answers /v1/querybatch with empty results (no vulnerabilities)
// and /vulns/{id} with full advisory records; tests arm advisories by
// package name so a poll discovers IDs in phase one and fetches records in
// phase two — exactly the two-phase production flow.
type fakeOSV struct {
	mu      sync.Mutex
	srv     *httptest.Server
	queries int
	last    []byte
	armed   map[string]map[string]any // package name → full OSV record
}

func newFakeOSV() *fakeOSV {
	o := &fakeOSV{armed: map[string]map[string]any{}}
	o.srv = httptest.NewServer(http.HandlerFunc(o.serve))
	return o
}

func (o *fakeOSV) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/querybatch" && r.Method == http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Queries []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"queries"`
		}
		_ = json.Unmarshal(body, &req)

		o.mu.Lock()
		results := make([]map[string]any, len(req.Queries))
		for i, q := range req.Queries {
			results[i] = map[string]any{}
			rec, ok := o.armed[q.Package.Name]
			if !ok {
				continue
			}
			id, _ := rec["id"].(string)
			modified, _ := rec["modified"].(string)
			results[i]["vulns"] = []map[string]string{{"id": id, "modified": modified}}
		}
		o.queries++
		o.last = body
		o.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	case strings.HasPrefix(r.URL.Path, "/vulns/") && r.Method == http.MethodGet:
		id := strings.TrimPrefix(r.URL.Path, "/vulns/")
		o.mu.Lock()
		var record map[string]any
		for _, rec := range o.armed {
			if rid, _ := rec["id"].(string); rid == id {
				record = rec
				break
			}
		}
		o.mu.Unlock()
		if record == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(record)
	default:
		http.NotFound(w, r)
	}
}

// arm advertises record for every query about pkgName.
func (o *fakeOSV) arm(pkgName string, record map[string]any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.armed[pkgName] = record
}

// disarm drops every armed advisory (fresh expectations per subtest).
func (o *fakeOSV) disarm() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.armed = map[string]map[string]any{}
}

func (o *fakeOSV) URL() string { return o.srv.URL + "/v1/querybatch" }

// VulnURL is the full-record template the server resolves IDs through.
func (o *fakeOSV) VulnURL() string { return o.srv.URL + "/vulns/{id}" }

func (o *fakeOSV) callCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.queries
}

// fakeIdP is a loopback OIDC provider: static authorize redirect (echoing
// state and nonce through a one-shot code), JWKS, token exchange, and
// userinfo — the exact endpoints NewOIDCAuthenticator derives from the
// issuer.
type fakeIdP struct {
	key   *rsa.PrivateKey
	srv   *httptest.Server
	mu    sync.Mutex
	email string
	codes map[string]struct{ redirectURI, nonce string }
}

// setEmail changes the subject the token endpoint and userinfo assert —
// tests drive provisioning, allowlist denial, and empty-email cases with it.
func (p *fakeIdP) setEmail(email string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.email = email
}

func newFakeIdP() *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generate idp key: %v", err))
	}
	p := &fakeIdP{key: key, email: e2eSSOEmail, codes: map[string]struct{ redirectURI, nonce string }{}}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	return p
}

func (p *fakeIdP) Issuer() string { return p.srv.URL }

func (p *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/oauth/authorize":
		// A real provider redirects back to the registered callback with
		// the exact state (and nonce) the client sent.
		q := r.URL.Query()
		code := randomHex(16)
		p.mu.Lock()
		p.codes[code] = struct{ redirectURI, nonce string }{
			redirectURI: q.Get("redirect_uri"), nonce: q.Get("nonce"),
		}
		p.mu.Unlock()
		back, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || q.Get("redirect_uri") == "" {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		vals := back.Query()
		vals.Set("code", code)
		vals.Set("state", q.Get("state"))
		back.RawQuery = vals.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	case "/.well-known/jwks.json":
		n := base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes())
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":"e2e-kid","alg":"RS256","use":"sig","n":%q,"e":%q}]}`, n, e)
	case "/oauth/token":
		_ = r.ParseForm()
		p.mu.Lock()
		stored, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		p.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"invalid_code"}`, http.StatusBadRequest)
			return
		}
		idToken := p.signIDToken(r.Form.Get("client_id"), stored.nonce)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "e2e-access", "token_type": "Bearer", "id_token": idToken,
		})
	case "/userinfo":
		p.mu.Lock()
		email := p.email
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "e2e-sso-sub", "email": email,
			"groups": []string{"platform-team"},
		})
	default:
		http.NotFound(w, r)
	}
}

func (p *fakeIdP) signIDToken(audience, nonce string) string {
	p.mu.Lock()
	email := p.email
	p.mu.Unlock()
	claims := map[string]any{
		"iss":   p.srv.URL,
		"aud":   audience,
		"sub":   "e2e-sso-sub",
		"email": email,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	// The e2e server verifies signature against this key's JWKS; a compact
	// RS256 JWT is produced via the same helper the auth tests use.
	return signRS256(p.key, claims)
}

// intelFeed serves the EPSS and KEV fakes: per-CVE scores for /epss and a
// catalog for /kev.json, with arm/fail switches per scenario.
type intelFeed struct {
	mu     sync.Mutex
	srv    *httptest.Server
	scores map[string]float64 // CVE → EPSS score
	kev    map[string]string  // CVE → dateAdded
	fail   bool
}

func newIntelFeed() *intelFeed {
	f := &intelFeed{scores: map[string]float64{}, kev: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

func (f *intelFeed) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	fail, scores, kev := f.fail, map[string]float64{}, map[string]string{}
	for k, v := range f.scores {
		scores[k] = v
	}
	for k, v := range f.kev {
		kev[k] = v
	}
	f.mu.Unlock()
	if fail {
		http.Error(w, "feed down", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/epss":
		data := []map[string]string{}
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			if score, ok := scores[cve]; ok {
				data = append(data, map[string]string{
					"cve": cve, "epss": fmt.Sprintf("%.4f", score),
					"percentile": "99.9", "date": "2026-09-01",
				})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "OK", "data": data})
	case "/kev.json":
		vulns := []map[string]string{}
		for cve, added := range kev {
			vulns = append(vulns, map[string]string{"cveID": cve, "dateAdded": added})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": vulns})
	default:
		http.NotFound(w, r)
	}
}

func (f *intelFeed) armEPSS(cve string, score float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scores[cve] = score
}

func (f *intelFeed) armKEV(cve, dateAdded string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kev[cve] = dateAdded
}

func (f *intelFeed) disarm() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scores = map[string]float64{}
	f.kev = map[string]string{}
}

func (f *intelFeed) setFail(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

func (f *intelFeed) EPSSURL() string { return f.srv.URL + "/epss" }
func (f *intelFeed) KEVURL() string  { return f.srv.URL + "/kev.json" }

// fakeServices holds the process-wide fakes for one E2E run.
type fakeServices struct {
	idp         *fakeIdP
	osv         *fakeOSV
	intel       *intelFeed
	notifySink  *captureSink
	trackerSink *captureSink
}

var fakes *fakeServices

func startFakes() {
	fakes = &fakeServices{
		idp:         newFakeIdP(),
		osv:         newFakeOSV(),
		intel:       newIntelFeed(),
		notifySink:  newCaptureSink(),
		trackerSink: newCaptureSink(),
	}
}

func stopFakes() {
	if fakes == nil {
		return
	}
	fakes.idp.srv.Close()
	fakes.osv.srv.Close()
	fakes.intel.srv.Close()
	fakes.notifySink.srv.Close()
	fakes.trackerSink.srv.Close()
}

// shrinkWatcherCadence lowers the per-project watcher poll interval default
// for the test database (see the call site for rationale).
func shrinkWatcherCadence(dsn string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx,
		"ALTER TABLE projects ALTER COLUMN cve_watcher_interval_seconds SET DEFAULT 1")
	return err
}

// fakeServerEnv is appended to every server boot so the fakes are wired
// before TestMain's health probe: watcher polls the fake OSV at 1s
// intervals, tracker/notify deliver to the capture sinks, SSO trusts the
// loopback IdP, and 127.0.0.1 is a trusted proxy for forwarded headers.
func fakeServerEnv(addr string) []string {
	if fakes == nil {
		return nil
	}
	return []string{
		"WATCHER_ENABLE=true",
		"WATCHER_OSV_ENDPOINT=" + fakes.osv.URL(),
		"WATCHER_OSV_VULN_ENDPOINT=" + fakes.osv.VulnURL(),
		"WATCHER_POLL_INTERVAL=1s",
		"WATCHER_WEBHOOK_URL=" + fakes.notifySink.URL() + "/notify",
		"WATCHER_WEBHOOK_URLS=" + fakes.trackerSink.URL() + "/tracker",
		"WATCHER_WEBHOOK_SIGNING_SECRET=" + e2eWebhookSecret,
		"TRACKER_PROVIDER=webhook",
		"TRACKER_PROJECT_ID=e2e-project",
		"TRACKER_API_TOKEN=e2e-token",
		"SSO_ENABLE=true",
		"SSO_ISSUER_URL=" + fakes.idp.Issuer(),
		"SSO_CLIENT_ID=" + e2eIdPClientID,
		"SSO_CLIENT_SECRET=" + e2eIdPClientSecret,
		"SSO_REDIRECT_URI=http://" + addr + "/api/v1/auth/sso/callback",
		"SSO_ALLOWED_DOMAINS=example.com",
		"SSO_ADMIN_GROUPS=platform-team",
		"TRUSTED_PROXIES=127.0.0.1/32",
		"INTEL_EPSS_ENDPOINT=" + fakes.intel.EPSSURL(),
		"INTEL_KEV_ENDPOINT=" + fakes.intel.KEVURL(),
		// A one-second TTL keeps the staleness contract observable.
		"INTEL_TTL=1s",
	}
}

// signRS256 signs a compact RS256 JWT (header carries the JWKS kid).
func signRS256(key *rsa.PrivateKey, claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"e2e-kid"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(fmt.Sprintf("marshal id_token claims: %v", err))
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(fmt.Sprintf("sign id_token: %v", err))
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// stringsKeep is a tiny helper for readable contains-assertions.
func stringsKeep(haystack, needle string) bool { return strings.Contains(haystack, needle) }
