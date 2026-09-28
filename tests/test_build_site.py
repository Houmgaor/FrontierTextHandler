"""web/build_site.py: every version of the site must be self-consistent."""

import os
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "web"))

import build_site  # noqa: E402


class TestBuildSite(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.site = build_site.build_site(Path(tmp.name) / "site")
        self.build = build_site.build_id(build_site._sources())

    def test_every_reference_between_files_is_versioned(self):
        names = [*build_site.STATIC_FILES, "app.zip"]
        pattern = re.compile(r"""["'](?:\./)?(%s)(\?v=\w+)?["']""" % "|".join(map(re.escape, names)))
        found = 0
        for name in build_site.STATIC_FILES:
            for match in pattern.finditer((self.site / name).read_text(encoding="utf-8")):
                found += 1
                self.assertEqual(match[2], f"?v={self.build}", f"{name}: {match[0]}")
        # index.html -> style.css, app.js; app.js -> editor.js, i18n.js,
        # worker.js; editor.js -> store.js; worker.js -> app.zip.
        self.assertGreaterEqual(found, 7)

    def test_build_id_is_embedded_where_checked(self):
        for name in build_site.STATIC_FILES:
            self.assertNotIn(build_site.BUILD_PLACEHOLDER, (self.site / name).read_text(encoding="utf-8"))
        for name in ("app.js", "worker.js"):
            self.assertIn(f'const BUILD = "{self.build}";', (self.site / name).read_text(encoding="utf-8"))
        bridge = zipfile.ZipFile(self.site / "app.zip").read("bridge.py").decode()
        self.assertIn(f'BUILD = "{self.build}"', bridge)

    def test_build_id_follows_the_sources(self):
        files = build_site._sources()
        self.assertEqual(build_site.build_id(files), self.build)
        files["src/common.py"] += b"\n# changed\n"
        self.assertNotEqual(build_site.build_id(files), self.build)


if __name__ == "__main__":
    unittest.main()
