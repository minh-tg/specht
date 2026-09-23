package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runProjectTeamsCmd executes the project-teams subtree on a test root that
// mirrors NewRootCmd's persistent --format wiring.
func runProjectTeamsCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newProjectTeamsCmd(d))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

func TestProjectTeamsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/teams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.Write([]byte(`[{"project_id":"p1","team_id":"t1","team_name":"Backend","role":"viewer"}]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runProjectTeamsCmd(t, d, "project-teams", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "Backend\tt1\tviewer\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestProjectTeamsListEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/teams", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runProjectTeamsCmd(t, d, "project-teams", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "No linked teams.") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestProjectTeamsListMissingProject(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runProjectTeamsCmd(t, d, "project-teams", "list")
	if err == nil || !strings.Contains(err.Error(), "--project is required for project-teams list") {
		t.Fatalf("expected missing project error, got %v", err)
	}
}

func TestProjectTeamsLink(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/teams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.Write([]byte(`{"project_id":"p1","team_id":"t1","team_name":"Backend","role":"editor"}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runProjectTeamsCmd(t, d, "project-teams", "link", "--project", "demo", "--team", "t1", "--role", "editor"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "linked Backend as editor\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestProjectTeamsLinkMissingFlags(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runProjectTeamsCmd(t, d, "project-teams", "link", "--project", "demo", "--team", "t1")
	if err == nil || !strings.Contains(err.Error(), "--project, --team, and --role are required for project-teams link") {
		t.Fatalf("expected missing flags error, got %v", err)
	}
}

func TestProjectTeamsUnlink(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/teams/t1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)
	if err := runProjectTeamsCmd(t, d, "project-teams", "unlink", "--project", "demo", "--team", "t1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "team unlinked") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestProjectTeamsUnlinkMissingFlags(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runProjectTeamsCmd(t, d, "project-teams", "unlink", "--project", "demo")
	if err == nil || !strings.Contains(err.Error(), "--project and --team are required for project-teams unlink") {
		t.Fatalf("expected missing flags error, got %v", err)
	}
}

func TestProjectTeamsLinkClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/teams", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runProjectTeamsCmd(t, d, "project-teams", "link", "--project", "demo", "--team", "t1", "--role", "editor"); err == nil {
		t.Fatal("expected client error")
	}
}
