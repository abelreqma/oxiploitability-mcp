import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from pack import pack


class PackTests(unittest.TestCase):
    def test_bundle_has_exact_files_and_executable_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            (bundle / "server").mkdir(parents=True)
            (bundle / "manifest.json").write_text(
                json.dumps({"manifest_version": "0.3", "server": {"type": "binary", "entry_point": "server/oxiploitability"}}),
                encoding="utf-8",
            )
            for name in ("LICENSE-MIT", "LICENSE-APACHE", "server/oxiploitability"):
                (bundle / name).write_bytes(name.encode())
            output = root / "bundle.mcpb"
            pack(bundle, output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {"manifest.json", "LICENSE-MIT", "LICENSE-APACHE", "server/oxiploitability"})
                self.assertEqual(archive.read("server/oxiploitability"), b"server/oxiploitability")
                self.assertTrue(stat.S_IMODE(archive.getinfo("server/oxiploitability").external_attr >> 16) & stat.S_IXUSR)
            (bundle / "extra.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bundle files do not match"):
                pack(bundle, output)


if __name__ == "__main__":
    unittest.main()
