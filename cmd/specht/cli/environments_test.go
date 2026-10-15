package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const environmentsJSON = `[{"id":"e1","name":"production","tier":"production","internet_facing":true,"data_sensitivity":"restricted"},{"id":"e2","name":"staging","tier":"staging","internet_facing":false,"data_sensitivity":"internal"}]`

func TestEnvironmentsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/environments", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(environmentsJSON)) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "environments", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	want := "e1\tproduction\tproduction\tinternet facing\trestricted\ne2\tstaging\tstaging\tinternal\tinternal\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestEnvironmentsListWhenThereAreNone(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/environments", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "environments", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "No environments.\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func environmentServer(t *testing.T, put *map[string]any) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/environments", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(environmentsJSON)) })
	mux.HandleFunc("/api/v1/projects/demo/environments/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(put)
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/demo/environments/")
		_, _ = w.Write([]byte(`{"id":"` + id + `","name":"production","tier":"` + (*put)["tier"].(string) + `","internet_facing":` + boolText((*put)["internet_facing"].(bool)) + `,"data_sensitivity":"` + (*put)["data_sensitivity"].(string) + `"}`))
	})
	return mux
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestEnvironmentsSetChangesOnlyWhatIsNamedAndKeepsTheRest(t *testing.T) {
	var put map[string]any
	d, out, _ := testDeps(t, environmentServer(t, &put))

	if err := runCmd(t, d, "environments", "set", "--project", "demo", "--env", "production", "--data-sensitivity", "confidential"); err != nil {
		t.Fatal(err)
	}
	if put["tier"] != "production" || put["internet_facing"] != true || put["data_sensitivity"] != "confidential" {
		t.Fatalf("put = %v: the tier and the exposure should have been kept", put)
	}
	if !strings.Contains(out.String(), "confidential") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestEnvironmentsSetCanTurnExposureOff(t *testing.T) {
	var put map[string]any
	d, _, _ := testDeps(t, environmentServer(t, &put))
	if err := runCmd(t, d, "environments", "set", "--project", "demo", "--env", "e1", "--internet-facing=false"); err != nil {
		t.Fatal(err)
	}
	if put["internet_facing"] != false {
		t.Fatalf("put = %v: false is a setting, not an absent flag", put)
	}
}

func TestEnvironmentsSetFindsByNameOrID(t *testing.T) {
	for _, ref := range []string{"staging", "e2"} {
		var put map[string]any
		d, _, _ := testDeps(t, environmentServer(t, &put))
		if err := runCmd(t, d, "environments", "set", "--project", "demo", "--env", ref, "--tier", "test"); err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if put["tier"] != "test" || put["data_sensitivity"] != "internal" {
			t.Fatalf("%s: put = %v", ref, put)
		}
	}
}

func TestEnvironmentsSetChecksWhatItCan(t *testing.T) {
	var put map[string]any
	d, _, _ := testDeps(t, environmentServer(t, &put))
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no project":      {[]string{"--env", "production", "--tier", "test"}, "--project"},
		"no environment":  {[]string{"--project", "demo", "--tier", "test"}, "--env"},
		"nothing to set":  {[]string{"--project", "demo", "--env", "production"}, "nothing to change"},
		"unknown":         {[]string{"--project", "demo", "--env", "qa", "--tier", "test"}, `no environment "qa"`},
		"server refusals": {[]string{"--project", "demo", "--env", "production", "--tier", "prod"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCmd(t, d, append([]string{"environments", "set"}, tc.args...)...)
			if name == "server refusals" {
				return // the server owns the vocabulary; covered by the end-to-end test
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}
