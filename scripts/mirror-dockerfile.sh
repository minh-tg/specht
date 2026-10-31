#!/usr/bin/env bash
# Prints the path of a Dockerfile whose base images come from IMAGE_PREFIX.
#
#   docker build -f "$(scripts/mirror-dockerfile.sh deploy/Dockerfile)" .
#
# The Dockerfiles name Docker Hub images as docker.io/library/<name>:<tag>@<digest>. CI sets
# IMAGE_PREFIX to its GHCR mirror (see .github/actions/image-source). This script then writes a
# copy with the prefix swapped in and prints the copy's path. The digest stays, and it is valid on
# the mirror because the mirror copies manifests byte for byte. With IMAGE_PREFIX unset, or set to
# the Docker Hub default, it prints the original path and the build is unchanged.
#
# MIRROR_DOCKERFILE_DIR picks the directory the copy goes in (default: a new temp directory). Compose
# builds through buildx bake, which refuses a Dockerfile outside its working directory, so
# scripts/compose-smoke.sh points it inside the repository.
set -euo pipefail

src="${1:?usage: scripts/mirror-dockerfile.sh <dockerfile>}"
hub="docker.io/library"
prefix="${IMAGE_PREFIX:-$hub}"

if [ "$prefix" = "$hub" ]; then
  echo "$src"
  exit 0
fi

out="${MIRROR_DOCKERFILE_DIR:-$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/mirror-dockerfile.XXXXXX")}"
dst="$out/$(basename "$src")"
sed -E "s#^(FROM[[:space:]]+(--[^[:space:]]+[[:space:]]+)*)$hub/#\\1$prefix/#" "$src" >"$dst"
if cmp -s "$src" "$dst"; then
  echo "mirror-dockerfile: no base image in $src names $hub/" >&2
  exit 1
fi
echo "$dst"
