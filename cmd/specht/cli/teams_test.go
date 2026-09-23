package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func runTeamsCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newTeamsCmd(d, s))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

func TestTeamsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[{"id":"t1","name":"Backend","description":"service owners"}]`)); err != nil {
			t.Errorf("write teams response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "list"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "Backend\tt1\tservice owners\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestTeamsListEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Errorf("write empty teams response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "list"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "No teams.\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestTeamsCreate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if _, err := w.Write([]byte(`{"id":"t1","name":"Backend"}`)); err != nil {
			t.Errorf("write created team response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "create", "--name", "Backend", "--description", "owners"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "team Backend (t1)\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestTeamsDelete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams/t1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "delete", "--id", "t1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "team deleted\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestTeamsMembers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams/t1/members", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[{"team_id":"t1","user_id":"u1","user_email":"dev@example.com","role":"member"}]`)); err != nil {
			t.Errorf("write team members response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "members", "--id", "t1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "dev@example.com\tu1\tmember\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestTeamsAdd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams/t1/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if _, err := w.Write([]byte(`{"team_id":"t1","user_id":"u1","role":"admin"}`)); err != nil {
			t.Errorf("write added team member response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "add", "--id", "t1", "--user", "u1", "--role", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "member u1 (admin)\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestTeamsRemove(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams/t1/members/u1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "remove", "--id", "t1", "--user", "u1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "member removed\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestTeamsRequiredFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "create", args: []string{"teams", "create"}, want: "--name is required for teams create"},
		{name: "delete", args: []string{"teams", "delete"}, want: "--id is required for teams delete"},
		{name: "members", args: []string{"teams", "members"}, want: "--id is required for teams members"},
		{name: "add", args: []string{"teams", "add", "--id", "t1", "--user", "u1"}, want: "--id, --user, and --role are required for teams add"},
		{name: "remove", args: []string{"teams", "remove", "--id", "t1"}, want: "--id and --user are required for teams remove"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _, _ := testDeps(t, http.NewServeMux())
			err := runTeamsCmd(t, d, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestTeamsClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/teams", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)

	if err := runTeamsCmd(t, d, "teams", "list"); err == nil {
		t.Fatal("expected client error")
	}
}
