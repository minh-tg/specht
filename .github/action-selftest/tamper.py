#!/usr/bin/env python3
"""Tamper with the adapter archive for this runner, keeping it valid.

The self-test serves the result from a second directory, so the action must
reject the archive on its SHA256SUMS line while the signature over SHA256SUMS
still verifies.

The tamper flips one byte of the LICENSE inside a copy of the archive and then
writes the archive back. The result still unpacks and still contains a runnable
adapter, so only the checksum check can reject it. Flipping a byte in the
compressed stream instead would also break decompression, and the case would
pass even with the checksum check removed.

Reads RUNNER_OS and RUNNER_ARCH to pick the same asset name the action does.

Usage: tamper.py VERSION DIR
"""

import io
import os
import sys
import tarfile
import zipfile

OS_NAMES = {"Linux": "linux", "macOS": "darwin", "Windows": "windows"}
ARCHES = {"X64": "amd64", "ARM64": "arm64"}
LICENSE = "LICENSE"


def flip_one_byte(data):
    if not data:
        return b"x"
    flipped = bytearray(data)
    flipped[len(flipped) // 2] ^= 0xFF
    return bytes(flipped)


def tamper_tar_gz(path):
    with tarfile.open(path, "r:gz") as archive:
        members = []
        for member in archive.getmembers():
            handle = archive.extractfile(member) if member.isfile() else None
            members.append((member, handle.read() if handle else None))
    with tarfile.open(path, "w:gz") as archive:
        for member, data in members:
            if data is None:
                archive.addfile(member)
                continue
            if member.name == LICENSE:
                data = flip_one_byte(data)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def tamper_zip(path):
    with zipfile.ZipFile(path) as archive:
        entries = [(info, archive.read(info)) for info in archive.infolist()]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for info, data in entries:
            if info.filename == LICENSE:
                data = flip_one_byte(data)
            archive.writestr(info, data)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: tamper.py VERSION DIR")
    version, directory = sys.argv[1], sys.argv[2]
    try:
        os_name = OS_NAMES[os.environ["RUNNER_OS"]]
        arch = ARCHES[os.environ["RUNNER_ARCH"]]
    except KeyError as exc:
        sys.exit("unsupported runner: %s" % exc)
    if os_name == "windows":
        path = os.path.join(directory, "specht-adapter_%s_%s_%s.zip" % (version, os_name, arch))
        tamper_zip(path)
    else:
        path = os.path.join(directory, "specht-adapter_%s_%s_%s.tar.gz" % (version, os_name, arch))
        tamper_tar_gz(path)
    print("rewrote %s with one flipped LICENSE byte" % path)


if __name__ == "__main__":
    main()
