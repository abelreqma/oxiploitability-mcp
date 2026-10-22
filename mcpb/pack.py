#!/usr/bin/env python3
"""Pack a staged binary bundle as an MCPB ZIP archive."""

import json
import shutil
import stat
import sys
import zipfile
from pathlib import Path


def pack(bundle: Path, output: Path) -> None:
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != "0.3" or manifest.get("server", {}).get("type") != "binary":
        raise ValueError("expected an MCPB 0.3 binary manifest")
    entry = manifest["server"]["entry_point"]
    if entry not in ("server/oxiploitability", "server/oxiploitability.exe"):
        raise ValueError("unexpected server entry point")
    expected = {"manifest.json", "LICENSE-MIT", "LICENSE-APACHE", entry}
    actual = {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}
    if actual != expected:
        raise ValueError(f"bundle files do not match manifest: {sorted(actual ^ expected)}")
    if any(path.is_symlink() for path in bundle.rglob("*")):
        raise ValueError("bundle must not contain symlinks")
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(expected):
            source = bundle / name
            mode = 0o755 if name == entry else 0o644
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with source.open("rb") as reader, archive.open(info, "w") as writer:
                shutil.copyfileobj(reader, writer)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: pack.py <staged-bundle-directory> <output.mcpb>")
    pack(Path(sys.argv[1]), Path(sys.argv[2]))
