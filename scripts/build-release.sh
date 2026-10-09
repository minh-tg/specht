#!/usr/bin/env bash
# Release archives for the adapter and the CLI.
#
# Usage: scripts/build-release.sh VERSION OUTDIR
#
# Cross-compiles specht-adapter and specht for every supported platform and
# writes one archive per binary and platform into OUTDIR, plus a SHA256SUMS
# manifest over all of them. The same script serves the v* tag release
# (release.yml) and the pull-request dry run (ci.yml), so the release path is
# exercised before a tag exists.
#
# Archives are reproducible: paths are trimmed, the VCS stamp is dropped,
# archive members are sorted, and every member mtime is pinned to
# SOURCE_DATE_EPOCH (the commit time by default). Windows zips are written by
# python3's zipfile module rather than whichever zip(1) a builder happens to
# have installed, so two builders produce the same bytes. Set SOURCE_DATE_EPOCH
# or COMMIT to override what the current checkout would produce.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: scripts/build-release.sh VERSION OUTDIR" >&2
  exit 2
fi

VERSION="$1"
OUTDIR="$2"

# The release workflow passes the tag without its leading "v", and the same
# string lands in the archive file names.
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: VERSION must be MAJOR.MINOR.PATCH with an optional -prerelease suffix, got '${VERSION}'" >&2
  exit 2
fi

command -v go >/dev/null 2>&1 || {
  echo "error: go is required to build the release binaries" >&2
  exit 2
}

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "error: SOURCE_DATE_EPOCH must be a unix timestamp, got '${SOURCE_DATE_EPOCH}'" >&2
  exit 2
fi

# The version and commit ldflags match deploy/Dockerfile, so the archives and
# the image are built with the same metadata. The values only land in packages
# that import internal/version, which today is the server alone.
LDFLAGS="-X github.com/minh-tg/specht/internal/version.Version=${VERSION} -X github.com/minh-tg/specht/internal/version.Commit=${COMMIT}"

echo "building ${VERSION} from ${COMMIT} with SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

PLATFORMS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)
# Two parallel arrays instead of an associative one: macOS ships bash 3.2,
# where a developer may run this outside the dev shell.
binary_names=(specht-adapter specht)
binary_packages=(./cmd/adapter ./cmd/specht)

mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
# Drop this script's own output from earlier runs; leave anything else alone.
rm -f "$OUTDIR"/*.tar.gz "$OUTDIR"/*.zip "$OUTDIR"/SHA256SUMS \
  "$OUTDIR"/SHA256SUMS.sig "$OUTDIR"/SHA256SUMS.pem

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# tar_file <archive> <member>... : sorted, ownership-independent, fixed mtime.
tar_file() {
  local archive="$1"
  shift
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    -cf - -C "$STAGE" "$@" | gzip -n -9 >"$archive"
}

# zip_file <archive> <member>... : Windows assets, always written by the
# python3 zipfile module. Picking between zip(1) and python3 by what a builder
# has installed makes the archive bytes depend on the builder, so there is one
# implementation; python3 is on the GitHub runners and in the dev shell.
# Members are sorted and carry fixed mtimes and permissions.
zip_file() {
  local archive="$1"
  shift
  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: building zip archives needs python3" >&2
    return 1
  fi
  local members=()
  local member
  for member in "$@"; do
    members+=("$STAGE/$member")
  done
  python3 - "$archive" "$SOURCE_DATE_EPOCH" "${members[@]}" <<-'PY'
		import os, sys, time, zipfile

		archive, epoch, *members = sys.argv[1:]
		# MS-DOS timestamps are two-second resolution and start at 1980-01-01.
		stamp = max(int(epoch), 315532800) // 2 * 2
		modes = {".exe": 0o755}

		with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
		    for path in sorted(members):
		        name = os.path.basename(path)
		        info = zipfile.ZipInfo(name, time.gmtime(stamp)[:6])
		        info.compress_type = zipfile.ZIP_DEFLATED
		        info.external_attr = (0o100000 | modes.get(os.path.splitext(name)[1], 0o644)) << 16
		        with open(path, "rb") as fh:
		            zf.writestr(info, fh.read())
	PY
}

for platform in "${PLATFORMS[@]}"; do
  goos="${platform%%/*}"
  goarch="${platform##*/}"
  for i in "${!binary_names[@]}"; do
    binary="${binary_names[$i]}"
    package="${binary_packages[$i]}"
    osname="$binary"
    if [[ "$goos" == windows ]]; then
      osname="$binary.exe"
    fi

    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
      -trimpath \
      -buildvcs=false \
      -ldflags "$LDFLAGS" \
      -o "$STAGE/$osname" "$package"
    cp "$ROOT/LICENSE" "$STAGE/LICENSE"
    touch -d "@${SOURCE_DATE_EPOCH}" "$STAGE/$osname" "$STAGE/LICENSE"

    base="${binary}_${VERSION}_${goos}_${goarch}"
    if [[ "$goos" == windows ]]; then
      zip_file "$OUTDIR/${base}.zip" "$osname" LICENSE
    else
      tar_file "$OUTDIR/${base}.tar.gz" "$osname" LICENSE
    fi
    rm -f "$STAGE/$osname" "$STAGE/LICENSE"
  done
done

cd "$OUTDIR"
export LC_ALL=C
shopt -s nullglob
archives=(*.tar.gz *.zip)
if ((${#archives[@]} == 0)); then
  echo "error: no archives were built" >&2
  exit 1
fi
# sha256sum format over bare file names, so consumers verify with
# "sha256sum -c SHA256SUMS" from the directory holding the downloads.
sha256sum "${archives[@]}" >SHA256SUMS
cd "$ROOT"

echo "built ${#archives[@]} archives and SHA256SUMS in ${OUTDIR}"
