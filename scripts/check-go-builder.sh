#!/usr/bin/env bash
# Fails when the Go builder image differs between the deploy Dockerfiles, or when it is not the Go
# release that CI tests.
#
#   scripts/check-go-builder.sh [repo-root]
#
# The Dockerfiles are the source of truth for what ships. Every golang base image under deploy/
# must be the same reference (tag and digest), and its version must equal the `toolchain` line in
# go.mod, which setup-go reads in CI. A Dependabot bump of one Dockerfile therefore fails here until
# the other Dockerfile and go.mod follow.
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$root"

images="$(grep -hE '^FROM[[:space:]]+(--[^[:space:]]+[[:space:]]+)*[^[:space:]]*/golang:' deploy/Dockerfile* |
  awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; break } }' | sort -u)"

if [ -z "$images" ]; then
  echo "check-go-builder: no golang base image found in deploy/Dockerfile*" >&2
  exit 1
fi

if [ "$(wc -l <<<"$images")" -ne 1 ]; then
  echo "check-go-builder: the deploy Dockerfiles use different Go builder images:" >&2
  grep -HE '^FROM.*/golang:' deploy/Dockerfile* >&2
  exit 1
fi

tag="${images#*golang:}"
builder="${tag%%-*}"
toolchain="$(sed -nE 's/^toolchain go(.+)$/\1/p' go.mod)"

if [ -z "$toolchain" ]; then
  echo "check-go-builder: go.mod has no toolchain line" >&2
  exit 1
fi

if [ "$builder" != "$toolchain" ]; then
  echo "check-go-builder: builder image has Go $builder but go.mod toolchain is go$toolchain" >&2
  exit 1
fi

echo "Go builder image and go.mod toolchain agree on $toolchain."
