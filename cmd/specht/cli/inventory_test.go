package cli

import (
	"net/http"
	"testing"
)

func TestTargetsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/targets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"t1","name":"payments-api","kind":"repository","locator":"git@example.com:shop/payments-api.git"},{"id":"t2","name":"alpine","kind":"container-image"}]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "targets", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	want := "t1\tpayments-api\trepository\tgit@example.com:shop/payments-api.git\nt2\talpine\tcontainer-image\t-\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestArtifactsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/artifacts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"a1","name":"payments","version":"1.4.2","artifact_type":"container-image","digest":"sha256:0123456789abcdef0123456789abcdef"},{"id":"a2","name":"sbom","artifact_type":"sbom"}]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "artifacts", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	want := "a1\tpayments 1.4.2\tcontainer-image\t0123456789ab\na2\tsbom\tsbom\t-\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestInventoryListsWhenThereAreNone(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/targets", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	mux.HandleFunc("/api/v1/projects/demo/artifacts", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`null`)) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "targets", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, d, "artifacts", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "No scan targets.\nNo artifacts.\n" {
		t.Fatalf("output = %q", out.String())
	}
}
