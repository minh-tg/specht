package main

import (
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/minh-tg/specht/internal/client"
	"github.com/minh-tg/specht/internal/domain"
)

// applyCIContext fills where the report came from: the repository, the pull or
// merge request and the CI run, so the UI can link back to them. A flag wins,
// then a value already in the input envelope, then what the CI provider sets.
//
// These values are display only, so a bad one never fails the upload: a URL
// the server would refuse is dropped with a note, and a title is cleaned and
// cut to the server's limit.
func applyCIContext(payload *client.IngestPayload, f *adapterFlags, stderr io.Writer) {
	if f.repoURL != "" {
		payload.RepositoryURL = f.repoURL
	}
	if payload.RepositoryURL == "" {
		payload.RepositoryURL = ciRepositoryURL()
	}
	if f.runURL != "" {
		payload.CIRunURL = f.runURL
	}
	if payload.CIRunURL == "" {
		payload.CIRunURL = ciRunURL()
	}
	if f.pullRequest > 0 {
		payload.PullRequestNumber = f.pullRequest
	}
	if payload.PullRequestNumber == 0 {
		number, title := ciPullRequest()
		payload.PullRequestNumber = number
		if payload.PullRequestTitle == "" {
			payload.PullRequestTitle = title
		}
	}

	payload.RepositoryURL = keepLink("repository URL", payload.RepositoryURL, stderr)
	payload.CIRunURL = keepLink("CI run URL", payload.CIRunURL, stderr)
	if payload.PullRequestNumber < 0 || payload.PullRequestNumber > math.MaxInt32 {
		writeDiagnostic(stderr, "note: pull request number %d is out of range and is not sent\n", payload.PullRequestNumber)
		payload.PullRequestNumber = 0
	}
	payload.PullRequestTitle = cleanTitle(payload.PullRequestTitle)
}

// keepLink returns s when the server will store it as a link, and "" with a
// note otherwise. The note never prints s: a URL with user info carries a
// credential, such as GitLab's CI_REPOSITORY_URL with its job token.
func keepLink(what, s string, stderr io.Writer) string {
	if s == "" {
		return ""
	}
	if problem := domain.LinkURLProblem(s); problem != "" {
		writeDiagnostic(stderr, "note: the %s is not sent, it %s\n", what, problem)
		return ""
	}
	return s
}

// cleanTitle turns control characters into spaces and cuts the title to the
// server's limit on a character boundary, so a title never fails the upload.
func cleanTitle(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= domain.MaxPullRequestTitleBytes {
		return s
	}
	cut := domain.MaxPullRequestTitleBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ciRepositoryURL returns the web address of the repository the build runs
// for, or "". GitLab's CI_REPOSITORY_URL is the clone URL with the job token
// in it and is never read.
func ciRepositoryURL() string {
	if server, repo := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"); server != "" && repo != "" {
		return strings.TrimRight(server, "/") + "/" + repo
	}
	return os.Getenv("CI_PROJECT_URL")
}

// ciRunURL returns the address of the CI run or job that uploads the report,
// or "".
func ciRunURL() string {
	server, repo, run := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID")
	if server != "" && repo != "" && run != "" {
		return strings.TrimRight(server, "/") + "/" + repo + "/actions/runs/" + run
	}
	return os.Getenv("CI_JOB_URL")
}

// ciPullRequest returns the number and title of the pull or merge request the
// build runs for, or 0 and "" for any other build. On GitHub they come from the
// pull_request event payload, on GitLab from a merge request pipeline.
func ciPullRequest() (int64, string) {
	switch os.Getenv("GITHUB_EVENT_NAME") {
	case "pull_request", "pull_request_target":
		if event, ok := readPullRequestEvent(); ok && event.PullRequest.Number > 0 {
			return event.PullRequest.Number, event.PullRequest.Title
		}
	}
	if iid, err := strconv.ParseInt(os.Getenv("CI_MERGE_REQUEST_IID"), 10, 64); err == nil && iid > 0 {
		return iid, os.Getenv("CI_MERGE_REQUEST_TITLE")
	}
	return 0, ""
}
