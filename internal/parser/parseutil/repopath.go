package parseutil

import "strings"

// workspaceRoots are the checkout directories of the CI systems and scanner
// containers Specht sees, one segment per entry. "*" matches any segment and
// "=" matches only the segment before it. The first root that matches wins.
var workspaceRoots = [][]string{
	// GitHub: Docker actions, hosted runners, container jobs. The two repository
	// segments of a GitHub workspace are the same name.
	{"github", "workspace"},
	{"home", "runner", "work", "*", "="},
	{"__w", "*", "="},
	// GitLab: /builds/<namespace>/<project>, or /builds/<runner>/<n>/... on a
	// runner with concurrent jobs. Two segments drop the runner and the job
	// slot, which change from run to run.
	{"builds", "*", "*"},
	{"home", "circleci", "project"},
	{"opt", "atlassian", "pipelines", "agent", "build"},
	{"home", "vsts", "work", "*", "s"},
	{"drone", "src"},
	// The mounts the tfsec and Dependency-Check container docs use.
	{"src"},
	{"workspace"},
	{"code"},
}

// userRoots are home directories: no repository root, but a prefix that names
// the machine's user and never the project.
var userRoots = [][]string{
	{"home", "*"},
	{"Users", "*"},
	{"root"},
}

// RepoPath cleans a path a scanner wrote and drops the checkout directory in
// front of it, so a file keeps one name across CI runners and mounts. Use it
// only for scanners that write absolute host paths (tfsec, Dependency-Check):
// Checkov and Grype write "/main.tf" for a file at the scan root, which a
// workspace root such as /src/ would cut wrong.
//
// A relative path is returned cleaned. An absolute path loses the first
// workspace root it starts with, then failing that a user's home directory. A
// path under neither stays absolute: a fixed mount such as /app is the same on
// every run. A root is dropped only when a file name is left after it.
func RepoPath(raw string) string {
	p := CleanFilePath(raw)
	if !strings.HasPrefix(p, "/") {
		return p
	}
	segs := strings.Split(p[1:], "/")
	for _, roots := range [][][]string{workspaceRoots, userRoots} {
		for _, root := range roots {
			if matchRoot(segs, root) {
				return strings.Join(segs[len(root):], "/")
			}
		}
	}
	return p
}

func matchRoot(segs, root []string) bool {
	if len(segs) <= len(root) {
		return false
	}
	for i, want := range root {
		switch want {
		case "*":
		case "=":
			if segs[i] != segs[i-1] {
				return false
			}
		default:
			if segs[i] != want {
				return false
			}
		}
	}
	return true
}
