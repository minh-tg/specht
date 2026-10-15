package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// body records the JSON a handler received.
func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var v map[string]any
	_ = json.NewDecoder(r.Body).Decode(&v)
	return v
}

func TestProjectsCreate(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		got = decodeBody(t, r)
		_, _ = w.Write([]byte(`{"slug":"payments","name":"Payments"}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "projects", "create", "--name", "Payments", "--slug", "payments", "--description", "the shop"); err != nil {
		t.Fatal(err)
	}
	if got["name"] != "Payments" || got["slug"] != "payments" || got["description"] != "the shop" {
		t.Fatalf("body = %v", got)
	}
	if out.String() != "project payments (Payments)\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestProjectsUpdateSendsOnlyWhatChanged(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/payments", func(w http.ResponseWriter, r *http.Request) {
		got = decodeBody(t, r)
		_, _ = w.Write([]byte(`{"slug":"payments","name":"Payments 2"}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "projects", "update", "payments", "--name", "Payments 2"); err != nil {
		t.Fatal(err)
	}
	if _, has := got["description"]; has || got["name"] != "Payments 2" {
		t.Fatalf("body = %v", got)
	}
	if out.String() != "project payments (Payments 2)\n" {
		t.Fatalf("output = %q", out.String())
	}
	if err := runCmd(t, d, "projects", "update", "payments"); err == nil || !strings.Contains(err.Error(), "nothing to change") {
		t.Fatalf("want 'nothing to change', got %v", err)
	}
}

func TestProjectsUpdateCanClearTheDescription(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/payments", func(w http.ResponseWriter, r *http.Request) {
		got = decodeBody(t, r)
		_, _ = w.Write([]byte(`{"slug":"payments","name":"Payments"}`))
	})
	d, _, _ := testDeps(t, mux)
	if err := runCmd(t, d, "projects", "update", "payments", "--description", ""); err != nil {
		t.Fatal(err)
	}
	if v, has := got["description"]; !has || v != "" {
		t.Fatalf("body = %v: an empty description is a request to clear it", got)
	}
}

func TestProjectsDeleteNeedsYes(t *testing.T) {
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/payments", func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"slug":"payments","name":"Payments"}`))
	})
	d, out, _ := testDeps(t, mux)

	err := runCmd(t, d, "projects", "delete", "payments")
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("want an error asking for --yes, got %v", err)
	}
	if called {
		t.Fatal("nothing may be deleted without --yes")
	}
	if err := runCmd(t, d, "projects", "delete", "payments", "--yes"); err != nil {
		t.Fatal(err)
	}
	if !called || out.String() != "project payments deleted\n" {
		t.Fatalf("called=%v output=%q", called, out.String())
	}
}

func TestMembers(t *testing.T) {
	mux := http.NewServeMux()
	var added map[string]any
	var removedPath string
	mux.HandleFunc("/api/v1/projects/demo/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			added = decodeBody(t, r)
			_, _ = w.Write([]byte(`{"project_id":"p","user_id":"u2","role":"manager","email":"ada@example.com"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"project_id":"p","user_id":"u1","role":"admin","email":"boss@example.com","display_name":"Boss"},{"project_id":"p","user_id":"u2","role":"member"}]`))
	})
	mux.HandleFunc("/api/v1/projects/demo/members/", func(w http.ResponseWriter, r *http.Request) {
		removedPath = r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "members", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "boss@example.com\tu1\tadmin\nu2\tu2\tmember\n" {
		t.Fatalf("list output = %q", out.String())
	}

	out.Reset()
	if err := runCmd(t, d, "members", "add", "--project", "demo", "--email", "ada@example.com", "--role", "manager"); err != nil {
		t.Fatal(err)
	}
	if added["email"] != "ada@example.com" || added["role"] != "manager" {
		t.Fatalf("add body = %v", added)
	}
	if _, has := added["user_id"]; has {
		t.Fatalf("exactly one of email and user_id: %v", added)
	}
	if out.String() != "ada@example.com\tu2\tmanager\n" {
		t.Fatalf("add output = %q", out.String())
	}

	out.Reset()
	if err := runCmd(t, d, "members", "add", "--project", "demo", "--user", "u3", "--role", "member"); err != nil {
		t.Fatal(err)
	}
	if added["user_id"] != "u3" {
		t.Fatalf("add by id body = %v", added)
	}

	out.Reset()
	if err := runCmd(t, d, "members", "remove", "--project", "demo", "--user", "u2"); err != nil {
		t.Fatal(err)
	}
	if removedPath != "DELETE /api/v1/projects/demo/members/u2" || out.String() != "member removed\n" {
		t.Fatalf("remove: %q %q", removedPath, out.String())
	}
}

func TestMembersAddNeedsExactlyOneWayToNameThePerson(t *testing.T) {
	d, _, _ := testDeps(t, http.NewServeMux())
	for name, args := range map[string][]string{
		"neither": {"members", "add", "--project", "demo", "--role", "member"},
		"both":    {"members", "add", "--project", "demo", "--role", "member", "--user", "u1", "--email", "a@b.c"},
	} {
		if err := runCmd(t, d, args...); err == nil || !strings.Contains(err.Error(), "--user or --email") {
			t.Fatalf("%s: want an error about --user or --email, got %v", name, err)
		}
	}
	if err := runCmd(t, d, "members", "add", "--project", "demo", "--email", "a@b.c"); err == nil || !strings.Contains(err.Error(), "--role") {
		t.Fatalf("want an error naming --role, got %v", err)
	}
}

func TestAPIKeys(t *testing.T) {
	mux := http.NewServeMux()
	var created map[string]any
	var revoked string
	mux.HandleFunc("/api/v1/auth/apikeys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			created = decodeBody(t, r)
			_, _ = w.Write([]byte(`{"id":"k1","name":"ci","key_prefix":"vuln_ab","raw_key":"vuln_abcdef0123456789","created_at":"2026-10-01T10:00:00Z"}`))
			return
		}
		if r.URL.Query().Get("project") != "demo" {
			t.Errorf("project = %q", r.URL.Query().Get("project"))
		}
		_, _ = w.Write([]byte(`[{"id":"k1","name":"ci","key_prefix":"vuln_ab","last_four":"6789","created_at":"2026-10-01T10:00:00Z"}]`))
	})
	mux.HandleFunc("/api/v1/auth/apikeys/", func(w http.ResponseWriter, r *http.Request) {
		revoked = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "api-keys", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "k1\tci\tvuln_ab...6789\t2026-10-01T10:00:00Z\n" {
		t.Fatalf("list output = %q", out.String())
	}

	out.Reset()
	if err := runCmd(t, d, "api-keys", "create", "--project", "demo", "--name", "ci"); err != nil {
		t.Fatal(err)
	}
	if created["project"] != "demo" || created["name"] != "ci" {
		t.Fatalf("create body = %v", created)
	}
	for _, want := range []string{"vuln_abcdef0123456789", "shown once"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("create output lacks %q: %q", want, out.String())
		}
	}

	out.Reset()
	if err := runCmd(t, d, "api-keys", "revoke", "--project", "demo", "--id", "k1"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(revoked, "DELETE /api/v1/auth/apikeys/k1") || out.String() != "key revoked\n" {
		t.Fatalf("revoke: %q %q", revoked, out.String())
	}
}

func TestUsers(t *testing.T) {
	mux := http.NewServeMux()
	var role map[string]any
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("email") != "ada" {
			t.Errorf("email filter = %q", r.URL.Query().Get("email"))
		}
		_, _ = w.Write([]byte(`[{"id":"u1","email":"ada@example.com","role":"admin","disabled":false},{"id":"u2","email":"bob@example.com","display_name":"Bob","role":"member","disabled":true}]`))
	})
	mux.HandleFunc("/api/v1/users/u1/role", func(w http.ResponseWriter, r *http.Request) {
		role = decodeBody(t, r)
		_, _ = w.Write([]byte(`{"id":"u1","email":"ada@example.com","role":"member","disabled":false}`))
	})
	mux.HandleFunc("/api/v1/users/u1/reset-link", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"link":"/reset/abc123","expires_at":"2026-10-16T10:00:00Z"}`))
	})
	mux.HandleFunc("/api/v1/users/u2/deactivate", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"u2","email":"bob@example.com","role":"member","disabled":true}`))
	})
	mux.HandleFunc("/api/v1/users/u2/reactivate", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"u2","email":"bob@example.com","role":"member","disabled":false}`))
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "users", "list", "--email", "ada"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "u1\tada@example.com\tadmin\tactive\nu2\tbob@example.com\tmember\tdeactivated\n" {
		t.Fatalf("list output = %q", out.String())
	}

	out.Reset()
	if err := runCmd(t, d, "users", "role", "--id", "u1", "--role", "member"); err != nil {
		t.Fatal(err)
	}
	if role["role"] != "member" || out.String() != "u1\tada@example.com\tmember\tactive\n" {
		t.Fatalf("role: %v %q", role, out.String())
	}

	out.Reset()
	if err := runCmd(t, d, "users", "reset-link", "--id", "u1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/reset/abc123", "2026-10-16T10:00:00Z", "once"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("reset-link output lacks %q: %q", want, out.String())
		}
	}

	out.Reset()
	if err := runCmd(t, d, "users", "deactivate", "--id", "u2"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "u2\tbob@example.com\tmember\tdeactivated\n" {
		t.Fatalf("deactivate output = %q", out.String())
	}
	out.Reset()
	if err := runCmd(t, d, "users", "reactivate", "--id", "u2"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "u2\tbob@example.com\tmember\tactive\n" {
		t.Fatalf("reactivate output = %q", out.String())
	}
}

func TestInvites(t *testing.T) {
	mux := http.NewServeMux()
	var created map[string]any
	var revoked string
	mux.HandleFunc("/api/v1/projects/demo/invites", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			created = decodeBody(t, r)
			_, _ = w.Write([]byte(`{"id":"i1","role":"member","created_at":"","expires_at":"2026-10-08T10:00:00Z","link":"/invite/tok123"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"i1","role":"member","email":"new@example.com","created_by":"boss@example.com","created_at":"","expires_at":"2026-10-08T10:00:00Z"},{"id":"i2","role":"manager","created_at":"","expires_at":"2026-10-09T10:00:00Z"}]`))
	})
	mux.HandleFunc("/api/v1/projects/demo/invites/", func(w http.ResponseWriter, r *http.Request) {
		revoked = r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "invites", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "i1\tmember\tnew@example.com\t2026-10-08T10:00:00Z\ni2\tmanager\tanyone\t2026-10-09T10:00:00Z\n" {
		t.Fatalf("list output = %q", out.String())
	}

	out.Reset()
	if err := runCmd(t, d, "invites", "create", "--project", "demo", "--role", "member", "--email", "new@example.com", "--days", "3"); err != nil {
		t.Fatal(err)
	}
	if created["role"] != "member" || created["email"] != "new@example.com" || created["expires_in_days"] != float64(3) {
		t.Fatalf("create body = %v", created)
	}
	for _, want := range []string{"/invite/tok123", "once", "2026-10-08T10:00:00Z"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("create output lacks %q: %q", want, out.String())
		}
	}

	out.Reset()
	if err := runCmd(t, d, "invites", "revoke", "--project", "demo", "--id", "i1"); err != nil {
		t.Fatal(err)
	}
	if revoked != "DELETE /api/v1/projects/demo/invites/i1" || out.String() != "invite revoked\n" {
		t.Fatalf("revoke: %q %q", revoked, out.String())
	}
}

func TestAdminCommandsNeedTheirFlags(t *testing.T) {
	d, _, _ := testDeps(t, http.NewServeMux())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"projects", "create", "--slug", "x"}, "--name"},
		{[]string{"projects", "create", "--name", "X"}, "--slug"},
		{[]string{"members", "list"}, "--project"},
		{[]string{"members", "remove", "--project", "demo"}, "--user"},
		{[]string{"api-keys", "create", "--project", "demo"}, "--name"},
		{[]string{"api-keys", "revoke", "--project", "demo"}, "--id"},
		{[]string{"users", "role", "--id", "u1"}, "--role"},
		{[]string{"users", "deactivate"}, "--id"},
		{[]string{"users", "reset-link"}, "--id"},
		{[]string{"invites", "create", "--project", "demo"}, "--role"},
		{[]string{"invites", "revoke", "--project", "demo"}, "--id"},
	} {
		if err := runCmd(t, d, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: want an error naming %s, got %v", tc.args, tc.want, err)
		}
	}
}
