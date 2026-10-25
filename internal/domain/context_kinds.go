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

// NormalizeTargetKind maps a parser supplied target kind onto the values the
// targets.kind CHECK accepts: repo, service, container_image, filesystem,
// iac_stack and package. Parsers pass scanner vocabulary through (Trivy's
// "repository" or "cyclonedx", Checkov's framework names), so an unknown or
// empty kind falls back to one derived from the scan type, and then to
// filesystem.
func NormalizeTargetKind(kind string, scanType ScanType) string {
	if k := targetKind(kind); k != "" {
		return k
	}
	if k := targetKind(string(scanType)); k != "" {
		return k
	}
	return "filesystem"
}

func targetKind(kind string) string {
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(kind)), "-", "_") {
	case "container_image", "image":
		return "container_image"
	case "repo", "repository", "git":
		return "repo"
	case "filesystem", "fs", "rootfs", "vm":
		return "filesystem"
	case "iac_stack", "iac", "config", "terraform", "terraform_plan", "kubernetes",
		"helm", "kustomize", "cloudformation", "dockerfile", "arm", "bicep",
		"serverless", "github_actions", "gitlab_ci", "ansible":
		return "iac_stack"
	case "package", "sbom", "lockfile", "cyclonedx", "spdx":
		return "package"
	case "service", "dast":
		return "service"
	}
	return ""
}
