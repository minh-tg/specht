package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const waiverJSON = `{"id":"w1","project_id":"p1","name":"Dev only","description":"d","enabled":true,"status":"approved","scope_all":false,"reason":"","decision_note":"","expires_at":"2026-12-31T23:59:59Z","conditions":[{"id":"c1","field":"severity","operator":"eq","value":"low"}],"contexts":[],"targets":[{"id":"t1","finding_id":"f1"}],"created_at":"","updated_at":""}`

func TestWaiversList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[` + waiverJSON + `,{"id":"w2","name":"Old","status":"pending","enabled":false}]`))
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "waivers", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	want := "w1\tapproved\tenabled\tDev only\t2026-12-31T23:59:59Z\nw2\tpending\tdisabled\tOld\t-\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestWaiversListWhenThereAreNone(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "waivers", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "No waivers.\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestWaiversGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers/w1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(waiverJSON)) })
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "waivers", "get", "--project", "demo", "--id", "w1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Name:", "Dev only", "Status:", "approved", "Expires:", "2026-12-31", "severity eq low", "finding f1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestWaiversCreate(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(waiverJSON))
	})
	d, out, _ := testDeps(t, mux)

	err := runCmd(t, d, "waivers", "create", "--project", "demo", "--name", "Dev only", "--description", "test fixtures",
		"--finding", "f1,f2", "--condition", "severity:eq:low", "--expires", "2026-12-31")
	if err != nil {
		t.Fatal(err)
	}
	if got["name"] != "Dev only" || got["description"] != "test fixtures" || got["expires_at"] != "2026-12-31T23:59:59Z" {
		t.Fatalf("body = %v", got)
	}
	if ids, _ := got["target_ids"].([]any); len(ids) != 2 {
		t.Fatalf("target_ids = %v", got["target_ids"])
	}
	conds, _ := got["conditions"].([]any)
	if len(conds) != 1 || conds[0].(map[string]any)["field"] != "severity" || conds[0].(map[string]any)["operator"] != "eq" || conds[0].(map[string]any)["value"] != "low" {
		t.Fatalf("conditions = %v", got["conditions"])
	}
	if out.String() != "w1\tapproved\tDev only\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestWaiversCreateAllScope(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(waiverJSON))
	})
	d, _, _ := testDeps(t, mux)
	if err := runCmd(t, d, "waivers", "create", "--project", "demo", "--name", "Everything", "--scope", "all"); err != nil {
		t.Fatal(err)
	}
	if got["scope"] != "all" {
		t.Fatalf("scope = %v", got["scope"])
	}
}

func TestWaiversCreateChecksWhatTheCommandLineCanCheck(t *testing.T) {
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers", func(http.ResponseWriter, *http.Request) { called = true })
	d, _, _ := testDeps(t, mux)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no project":    {[]string{"waivers", "create", "--name", "x"}, "--project"},
		"no name":       {[]string{"waivers", "create", "--project", "demo"}, "--name"},
		"bad condition": {[]string{"waivers", "create", "--project", "demo", "--name", "x", "--condition", "severity"}, "--condition"},
		"bad expiry":    {[]string{"waivers", "create", "--project", "demo", "--name", "x", "--expires", "never"}, "--expires"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCmd(t, d, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error naming %s, got %v", tc.want, err)
			}
		})
	}
	if called {
		t.Fatal("nothing invalid may reach the server")
	}
}

func TestWaiversRequest(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers/requests", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"id":"w9","name":"Request","status":"pending","enabled":true}`))
	})
	d, out, _ := testDeps(t, mux)

	err := runCmd(t, d, "waivers", "request", "--project", "demo", "--finding", "f1", "--reason", "needs a vendor fix", "--expires", "2026-12-31")
	if err != nil {
		t.Fatal(err)
	}
	if got["reason"] != "needs a vendor fix" || got["expires_at"] != "2026-12-31T23:59:59Z" {
		t.Fatalf("body = %v", got)
	}
	if ids, _ := got["target_ids"].([]any); len(ids) != 1 || ids[0] != "f1" {
		t.Fatalf("target_ids = %v", got["target_ids"])
	}
	if out.String() != "w9\tpending\tRequest\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestWaiversRequestNeedsFindingsReasonAndExpiry(t *testing.T) {
	d, _, _ := testDeps(t, http.NewServeMux())
	base := []string{"waivers", "request", "--project", "demo"}
	for flag, args := range map[string][]string{
		"--finding": {"--reason", "r", "--expires", "2026-12-31"},
		"--reason":  {"--finding", "f1", "--expires", "2026-12-31"},
		"--expires": {"--finding", "f1", "--reason", "r"},
	} {
		err := runCmd(t, d, append(append([]string{}, base...), args...)...)
		if err == nil || !strings.Contains(err.Error(), flag) {
			t.Fatalf("want an error naming %s, got %v", flag, err)
		}
	}
}

func TestWaiverDecisions(t *testing.T) {
	for _, tc := range []struct {
		cmd, path, method string
		args              []string
		wantNote          string
		out               string
	}{
		{"approve", "/approve", http.MethodPost, []string{"--note", "fine"}, "fine", "w1\tapproved\tDev only\n"},
		{"reject", "/reject", http.MethodPost, []string{"--note", "no"}, "no", "w1\tapproved\tDev only\n"},
		{"withdraw", "/withdraw", http.MethodPost, nil, "", "w1\tapproved\tDev only\n"},
		{"toggle", "/toggle", http.MethodPost, nil, "", "w1\tapproved\tDev only\n"},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			var note string
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/projects/demo/waivers/w1"+tc.path, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method {
					t.Errorf("method = %s", r.Method)
				}
				var body map[string]string
				_ = json.NewDecoder(r.Body).Decode(&body)
				note = body["note"]
				_, _ = w.Write([]byte(waiverJSON))
			})
			d, out, _ := testDeps(t, mux)
			args := append([]string{"waivers", tc.cmd, "--project", "demo", "--id", "w1"}, tc.args...)
			if err := runCmd(t, d, args...); err != nil {
				t.Fatal(err)
			}
			if note != tc.wantNote {
				t.Fatalf("note = %q, want %q", note, tc.wantNote)
			}
			if out.String() != tc.out {
				t.Fatalf("output = %q", out.String())
			}
		})
	}
}

func TestWaiversDelete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers/w1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "waivers", "delete", "--project", "demo", "--id", "w1"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "waiver deleted\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestWaiversEvents(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/waivers/w1/events", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"e1","waiver_id":"w1","event_type":"approved","actor_name":"Ada","created_at":"2026-10-01T10:00:00Z"}]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "waivers", "events", "--project", "demo", "--id", "w1"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "2026-10-01T10:00:00Z\tapproved\tAda\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestWaiverCommandsNeedAProjectAndAnID(t *testing.T) {
	d, _, _ := testDeps(t, http.NewServeMux())
	for _, sub := range []string{"get", "approve", "reject", "withdraw", "toggle", "delete", "events"} {
		if err := runCmd(t, d, "waivers", sub, "--project", "demo"); err == nil || !strings.Contains(err.Error(), "--id") {
			t.Fatalf("%s: want an error naming --id, got %v", sub, err)
		}
		if err := runCmd(t, d, "waivers", sub, "--id", "w1"); err == nil || !strings.Contains(err.Error(), "--project") {
			t.Fatalf("%s: want an error naming --project, got %v", sub, err)
		}
	}
}
