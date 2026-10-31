#!/usr/bin/env bash
# Prints the images CI mirrors, one name:tag[@digest] per line, relative to docker.io/library/.
#
# Two sources: .github/mirror-images.txt for images no Dockerfile names, and the docker.io/library
# FROM lines of the deploy Dockerfiles, so a digest bump there reaches the mirror without a second
# edit. The mirror workflow copies each line and the image-source action checks that each exists.
set -euo pipefail
cd "$(dirname "$0")/.."

{
  sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' .github/mirror-images.txt
  sed -nE 's#^FROM[[:space:]]+(--[^[:space:]]+[[:space:]]+)*docker\.io/library/([^[:space:]]+).*#\2#p' \
    deploy/Dockerfile deploy/Dockerfile.adapter
} | sort -u
