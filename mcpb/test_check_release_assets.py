import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from check_release_assets import BUNDLES, TARGETS, check


class ReleaseAssetTests(unittest.TestCase):
    def test_complete_assets_pass_and_corruption_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for target in TARGETS:
                base = f"oxiploitability-mcp-{target}"
                if "windows" in target:
                    path = root / f"{base}.zip"
                    with zipfile.ZipFile(path, "w") as archive:
                        archive.writestr("oxiploitability.exe", b"binary")
                else:
                    path = root / f"{base}.tar.gz"
                    with tarfile.open(path, "w:gz") as archive:
                        info = tarfile.TarInfo("oxiploitability")
                        info.size = 6
                        archive.addfile(info, io.BytesIO(b"binary"))
                self.write_checksum(path, root / f"{base}.sha256")
            for bundle in BUNDLES:
                path = root / f"oxiploitability-mcp-{bundle}.mcpb"
                entry = "server/oxiploitability.exe" if bundle.startswith("win32") else "server/oxiploitability"
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("manifest.json", json.dumps({"server": {"entry_point": entry}}))
                    for name in ("LICENSE-MIT", "LICENSE-APACHE", entry):
                        archive.writestr(name, b"content")
                self.write_checksum(path, root / f"{path.name}.sha256")
            check(root)
            path = root / "oxiploitability-mcp-linux-x86_64.mcpb"
            path.write_bytes(path.read_bytes() + b"corruption")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                check(root)

    @staticmethod
    def write_checksum(path: Path, checksum: Path) -> None:
        checksum.write_text(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n", encoding="ascii")


if __name__ == "__main__":
    unittest.main()
