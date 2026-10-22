#!/usr/bin/env python3
"""Check the complete draft release before making it public."""

import hashlib
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path


TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
)
BUNDLES = (
    "darwin-universal",
    "linux-x86_64",
    "linux-aarch64",
    "win32-x86_64",
)


def check(directory: Path) -> None:
    payloads = {}
    for target in TARGETS:
        base = f"oxiploitability-mcp-{target}"
        extension = ".zip" if "windows" in target else ".tar.gz"
        payloads[base + extension] = base + ".sha256"
    for bundle in BUNDLES:
        name = f"oxiploitability-mcp-{bundle}.mcpb"
        payloads[name] = name + ".sha256"
    expected = set(payloads) | set(payloads.values())
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != expected:
        raise ValueError(f"release asset mismatch: {sorted(actual ^ expected)}")

    for name, checksum_name in payloads.items():
        line = (directory / checksum_name).read_text(encoding="ascii").strip()
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](\S+)", line)
        if not match or match.group(2) != name:
            raise ValueError(f"invalid checksum file: {checksum_name}")
        with (directory / name).open("rb") as payload:
            digest = hashlib.file_digest(payload, "sha256").hexdigest()
        if digest != match.group(1):
            raise ValueError(f"checksum mismatch: {name}")
        if name.endswith(".mcpb"):
            with zipfile.ZipFile(directory / name) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                entry = manifest["server"]["entry_point"]
                if set(archive.namelist()) != {"manifest.json", "LICENSE-MIT", "LICENSE-APACHE", entry}:
                    raise ValueError(f"bundle contents mismatch: {name}")
        elif name.endswith(".zip"):
            with zipfile.ZipFile(directory / name) as archive:
                if set(archive.namelist()) != {"oxiploitability.exe"}:
                    raise ValueError(f"binary archive contents mismatch: {name}")
        else:
            with tarfile.open(directory / name, "r:gz") as archive:
                members = archive.getmembers()
                if len(members) != 1 or members[0].name != "oxiploitability" or not members[0].isfile():
                    raise ValueError(f"binary archive contents mismatch: {name}")
    print("All 18 release assets and their checksums passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: check_release_assets.py <downloaded-assets-directory>")
    check(Path(sys.argv[1]))
