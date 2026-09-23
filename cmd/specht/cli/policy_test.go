package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runPolicyCmd executes the policy subtree on a test root that mirrors
// NewRootCmd's persistent --format wiring. (NewRootCmd does not register
// policy yet; root.go is out of scope for this change.)
func runPolicyCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newPolicyCmd(d, s))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

const policyEffectiveBody = `{"template_name":"baseline","template_version":2,` +
	`"severity_floor":"high","severity_source":"template",` +
	`"watcher_gate":"block","watcher_source":"override"}`

func TestPolicyTemplates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy-templates", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[{"id":"t1","name":"baseline","description":"d","version":2}]`)); err != nil {
			t.Errorf("write policy templates response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "templates"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "baseline\tt1\tv2\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyTemplatesEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy-templates", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Errorf("write empty policy templates response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "templates"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "No policy templates.") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyCreate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy-templates", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"id":"t1","name":"baseline","version":1}`)); err != nil {
			t.Errorf("write created policy template response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "create", "--name", "baseline"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "template baseline (t1)\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyCreateMissingName(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "create")
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("expected missing name error, got %v", err)
	}
}

func TestPolicyCreateBadDefinition(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "create", "--name", "n", "--definition", "nope")
	if err == nil || !strings.Contains(err.Error(), `invalid --definition "nope": want a JSON object`) {
		t.Fatalf("expected invalid definition error, got %v", err)
	}
}

func TestPolicyUpdate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy-templates/t1", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"id":"t1","name":"baseline","version":3}`)); err != nil {
			t.Errorf("write updated policy template response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "update", "--id", "t1", "--name", "baseline"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "template baseline v3\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyUpdateMissingID(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "update", "--name", "n")
	if err == nil || !strings.Contains(err.Error(), "--id is required for policy update") {
		t.Fatalf("expected missing id error, got %v", err)
	}
}

func TestPolicyUpdateMissingName(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "update", "--id", "t1")
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("expected missing name error, got %v", err)
	}
}

func TestPolicyDelete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy-templates/t1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "delete", "--id", "t1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "template deleted") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyDeleteMissingID(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "delete")
	if err == nil || !strings.Contains(err.Error(), "--id is required for policy delete") {
		t.Fatalf("expected missing id error, got %v", err)
	}
}

func TestPolicyApply(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/policy", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(policyEffectiveBody)); err != nil {
			t.Errorf("write effective policy response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "apply", "--project", "demo", "--template", "baseline"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "policy: floor=high (template) watcher=block (override)\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyApplyMissingProject(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "apply")
	if err == nil || !strings.Contains(err.Error(), "--project is required for policy apply") {
		t.Fatalf("expected missing project error, got %v", err)
	}
}

func TestPolicyOverrides(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/policy/overrides", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(policyEffectiveBody)); err != nil {
			t.Errorf("write effective policy response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "overrides", "--project", "demo", "--set", `{"severity_floor":"high"}`); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "policy: floor=high (template) watcher=block (override)\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyOverridesMissingProject(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "overrides")
	if err == nil || !strings.Contains(err.Error(), "--project is required for policy overrides") {
		t.Fatalf("expected missing project error, got %v", err)
	}
}

func TestPolicyOverridesBadSet(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "overrides", "--project", "demo", "--set", "nope")
	if err == nil || !strings.Contains(err.Error(), `invalid --set "nope": want a JSON object`) {
		t.Fatalf("expected invalid set error, got %v", err)
	}
}

func TestPolicyEffectiveHuman(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/policy", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(policyEffectiveBody)); err != nil {
			t.Errorf("write effective policy response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "effective", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "template: baseline v2\n") {
		t.Fatalf("unexpected output: %q", got)
	}
	if !strings.Contains(got, "floor=high (template) watcher=block (override)\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyEffectiveNoTemplate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/policy", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"severity_floor":"high","severity_source":"default",` +
			`"watcher_gate":"warn","watcher_source":"default"}`)); err != nil {
			t.Errorf("write policy without template response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "effective", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "template: (none)\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyEffectiveJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/policy", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(policyEffectiveBody)); err != nil {
			t.Errorf("write effective policy response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPolicyCmd(t, d, "policy", "effective", "--project", "demo", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"severity_floor": "high"`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPolicyEffectiveMissingProject(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "effective")
	if err == nil || !strings.Contains(err.Error(), "--project is required for policy effective") {
		t.Fatalf("expected missing project error, got %v", err)
	}
}

func TestPolicyEffectiveInvalidFormat(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPolicyCmd(t, d, "policy", "effective", "--project", "demo", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `invalid --format "yaml": want human or json`) {
		t.Fatalf("expected invalid format error, got %v", err)
	}
}
