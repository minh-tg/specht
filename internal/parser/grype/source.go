package grype

import (
	"encoding/json"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
)

// grypeSource is the report's own record of what it scanned. Unlike a match
// location it exists whether or not the scan found anything, so a clean rescan
// names the same target as the scan that reported findings.
type grypeSource struct {
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"`
}

// grypeSourceTarget is source.target when it is an object, as it is for an
// image. A directory or file scan may write the path as a plain string.
type grypeSourceTarget struct {
	UserInput   string   `json:"userInput"`
	Path        string   `json:"path"`
	Tags        []string `json:"tags"`
	RepoDigests []string `json:"repoDigests"`
}

// transportPrefixes name how Grype fetched an image. They are not part of the
// image reference, so "docker:alpine:3.20" and "alpine:3.20" are one target.
var transportPrefixes = []string{"docker:", "podman:", "registry:", "containerd:"}

// archivePrefixes mark user input that is a file or directory on disk, not a
// registry reference, so a ":" in it is not a tag.
var archivePrefixes = []string{"docker-archive:", "oci-archive:", "oci-dir:", "singularity:"}

// sourceIdentity reads the scan target from source.target. ok is false when
// the source names nothing usable and the caller must fall back to the match
// locations.
func sourceIdentity(src grypeSource) (target domain.TargetInfo, scanType domain.ScanType, ok bool) {
	ref := sourceReference(src.Target)
	if ref == "" {
		return domain.TargetInfo{}, "", false
	}
	if src.Type != "image" {
		return domain.TargetInfo{Kind: "filesystem", Identifier: ref}, domain.ScanTypeFilesystem, true
	}
	for _, prefix := range archivePrefixes {
		if strings.HasPrefix(ref, prefix) {
			return domain.TargetInfo{Kind: "filesystem", Identifier: ref}, domain.ScanTypeImage, true
		}
	}
	for _, prefix := range transportPrefixes {
		if rest, found := strings.CutPrefix(ref, prefix); found && rest != "" {
			ref = rest
			break
		}
	}
	return domain.TargetInfo{Kind: "container_image", Identifier: ref}, domain.ScanTypeImage, true
}

// sourceReference returns what the user asked Grype to scan: the string form
// of source.target, or userInput, path or the first tag of the object form.
// Image ids and digests are not used, since they change with every build.
func sourceReference(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var obj grypeSourceTarget
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	for _, candidate := range []string{obj.UserInput, obj.Path} {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			return candidate
		}
	}
	for _, tag := range obj.Tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			return tag
		}
	}
	for _, digest := range obj.RepoDigests {
		if digest = strings.TrimSpace(digest); digest != "" {
			return digest
		}
	}
	return ""
}
