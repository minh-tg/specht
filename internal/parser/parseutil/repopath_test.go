package parseutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRepoPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"relative stays", "infra/a/main.tf", "infra/a/main.tf"},
		{"relative is cleaned", "./infra/../infra/a/main.tf", "infra/a/main.tf"},
		{"container mount", "/src/infra/a/main.tf", "infra/a/main.tf"},
		{"github docker action", "/github/workspace/infra/a/main.tf", "infra/a/main.tf"},
		{"github hosted runner", "/home/runner/work/specht/specht/infra/a/main.tf", "infra/a/main.tf"},
		{"github container job", "/__w/specht/specht/infra/a/main.tf", "infra/a/main.tf"},
		{"gitlab project dir", "/builds/acme/specht/infra/a/main.tf", "infra/a/main.tf"},
		{"gitlab concurrent runner", "/builds/x/1/infra/a/main.tf", "infra/a/main.tf"},
		{"circleci", "/home/circleci/project/infra/a/main.tf", "infra/a/main.tf"},
		{"bitbucket", "/opt/atlassian/pipelines/agent/build/infra/a/main.tf", "infra/a/main.tf"},
		{"azure", "/home/vsts/work/1/s/infra/a/main.tf", "infra/a/main.tf"},
		{"drone", "/drone/src/infra/a/main.tf", "infra/a/main.tf"},
		// The GitHub rule wants one repository name twice. a/b is not a
		// workspace, so only the home of the user "runner" goes.
		{"github work with two names", "/home/runner/work/a/b/x.tf", "work/a/b/x.tf"},
		{"linux home", "/home/minh/projects/specht/main.tf", "projects/specht/main.tf"},
		{"mac home", "/Users/minh/specht/main.tf", "specht/main.tf"},
		{"root home", "/root/specht/main.tf", "specht/main.tf"},
		{"unknown mount stays", "/app/nginx-1.0.exe", "/app/nginx-1.0.exe"},
		{"root without a file stays", "/src", "/src"},
		{"gitlab without a file stays", "/builds/x/1", "/builds/x/1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RepoPath(tt.in))
		})
	}
}

func TestRepoPathNamesAFileTheSameFromEveryCheckout(t *testing.T) {
	want := RepoPath("/src/infra/a/main.tf")
	for _, p := range []string{
		"/github/workspace/infra/a/main.tf",
		"/builds/x/1/infra/a/main.tf",
		"/home/runner/work/specht/specht/infra/a/main.tf",
	} {
		assert.Equal(t, want, RepoPath(p), p)
	}
}
