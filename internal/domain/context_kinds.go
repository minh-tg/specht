package domain

import "strings"

// ArtifactTypes lists the values the artifacts.artifact_type CHECK accepts.
var ArtifactTypes = []string{
	"container_image",
	"sbom",
	"repository_snapshot",
	"filesystem",
	"sarif",
	"iac_stack",
}

// NormalizeArtifactType maps a client or parser supplied artifact type onto
// ArtifactTypes. Case is ignored and hyphens count as underscores, so
// "container-image" is accepted. ok is false for anything else.
func NormalizeArtifactType(s string) (artifactType string, ok bool) {
	v := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", "_")
	for _, t := range ArtifactTypes {
		if v == t {
			return t, true
		}
	}
	return "", false
}

// ArtifactTypeForScan is the artifact type assumed when neither the request
// nor the parser names one. A DAST scan has no artifact in this vocabulary,
// so it and unknown scan types return "".
func ArtifactTypeForScan(scanType ScanType) string {
	switch scanType {
	case ScanTypeImage:
		return "container_image"
	case ScanTypeSBOM:
		return "sbom"
	case ScanTypeRepository:
		return "repository_snapshot"
	case ScanTypeFilesystem, ScanTypeLockfile:
		return "filesystem"
	case ScanTypeIaC:
		return "iac_stack"
	}
	return ""
}
