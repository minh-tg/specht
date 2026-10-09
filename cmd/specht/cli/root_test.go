package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/client"
	"github.com/minh-tg/specht/internal/version"
)

func TestRootRegistersProjectTeams(t *testing.T) {
	var gotPath string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`[{"project_id":"p1","team_id":"t1","team_name":"Backend","role":"viewer"}]`)),
			Header:     make(http.Header),
		}, nil
	})
	var out bytes.Buffer
	d := Deps{
		NewClient: func() (*client.Client, error) {
			return client.New("http://test", client.WithHTTPClient(&http.Client{Transport: transport})), nil
		},
		Out:  &out,
		ErrW: io.Discard,
	}

	if err := runCmd(t, d, "project-teams", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/projects/demo/teams" {
		t.Fatalf("request path = %q", gotPath)
	}
	if got := out.String(); got != "Backend\tt1\tviewer\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestRootRegistersTeams(t *testing.T) {
	var gotPath string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`[{"id":"t1","name":"Backend","description":"owners"}]`)),
			Header:     make(http.Header),
		}, nil
	})
	var out bytes.Buffer
	d := Deps{
		NewClient: func() (*client.Client, error) {
			return client.New("http://test", client.WithHTTPClient(&http.Client{Transport: transport})), nil
		},
		Out:  &out,
		ErrW: io.Discard,
	}

	if err := runCmd(t, d, "teams", "list"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/teams" {
		t.Fatalf("request path = %q", gotPath)
	}
	if got := out.String(); got != "Backend\tt1\towners\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestRootRegistersWatcher(t *testing.T) {
	var gotPath string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"healthy":true}`)),
			Header:     make(http.Header),
		}, nil
	})
	var out bytes.Buffer
	d := Deps{
		NewClient: func() (*client.Client, error) {
			return client.New("http://test", client.WithHTTPClient(&http.Client{Transport: transport})), nil
		},
		Out:  &out,
		ErrW: io.Discard,
	}

	if err := runCmd(t, d, "watcher", "status"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/watcher/status" {
		t.Fatalf("request path = %q", gotPath)
	}
}

func TestExecuteContextCancelsAPIRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(requestStarted)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errW bytes.Buffer
	d := Deps{
		NewClient: func() (*client.Client, error) {
			return client.New("http://test", client.WithHTTPClient(&http.Client{Transport: transport})), nil
		},
		Out:  io.Discard,
		ErrW: &errW,
	}

	done := make(chan int, 1)
	go func() {
		done <- ExecuteContext(ctx, []string{"projects", "list"}, d)
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("API request did not start")
	}
	cancel()
	select {
	case code := <-done:
		if code != exitFailure {
			t.Fatalf("exit code = %d, want %d; stderr = %q", code, exitFailure, errW.String())
		}
		if !bytes.Contains(errW.Bytes(), []byte("context canceled")) {
			t.Fatalf("stderr does not report cancellation: %q", errW.String())
		}
	case <-time.After(time.Second):
		t.Fatal("command did not stop after context cancellation")
	}
}

func TestExecuteMapsExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		response string
		newError error
		want     int
	}{
		{name: "passed gate", response: `{"threshold_breached":false,"blocking_count":0}`, want: 0},
		{name: "breached gate", response: `{"threshold_breached":true,"blocking_count":1}`, want: 1},
		{name: "runtime error", newError: errors.New("client unavailable"), want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errW bytes.Buffer
			d := Deps{
				NewClient: func() (*client.Client, error) {
					if tt.newError != nil {
						return nil, tt.newError
					}
					transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(tt.response)),
							Header:     make(http.Header),
						}, nil
					})
					return client.New("http://test", client.WithHTTPClient(&http.Client{Transport: transport})), nil
				},
				Out:  &out,
				ErrW: &errW,
			}

			got := Execute([]string{"gate", "check", "--project", "demo"}, d)
			if got != tt.want {
				t.Fatalf("exit code = %d, want %d; stderr = %q", got, tt.want, errW.String())
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestRootVersionFlag(t *testing.T) {
	var out bytes.Buffer
	d := Deps{Out: &out, ErrW: io.Discard}

	if err := runCmd(t, d, "--version"); err != nil {
		t.Fatal(err)
	}
	if want := "specht version " + version.String() + "\n"; out.String() != want {
		t.Fatalf("--version output = %q, want %q", out.String(), want)
	}
}
