"""
Assemble the static web interface into a folder GitHub Pages can serve.

    python web/build_site.py [OUT_DIR]      # default: _site

The Python sources run in the browser through Pyodide. They are shipped as
a single ``app.zip`` (``bridge.py`` plus the ``src`` package with
``headers.json``) so the worker downloads one file instead of one request
per module. Serve the result with ``python -m http.server -d _site``.

GitHub Pages lets browsers cache every file for 10 minutes, each on its own
clock, so right after a deploy a browser could combine a new page with an
old worker. To keep each version self-consistent, the build:

- appends ``?v=<build id>`` to every reference between the site's files,
  so a new page never picks up an old cached file;
- replaces ``__BUILD__`` in app.js, worker.js and bridge.py with the build
  id, which the page checks against the worker's at startup, in case a
  mix still gets through.

The build id is a hash of the site's sources.
"""

import hashlib
import io
import re
import shutil
import sys
import zipfile
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
STATIC_FILES = ["index.html", "style.css", "app.js", "editor.js", "store.js", "i18n.js", "worker.js"]
BUILD_PLACEHOLDER = "__BUILD__"

# "file.js", './file.js' or "app.zip" in quotes, for any file of the site.
_REFERENCE = re.compile(
    r"""(["'])(\./)?(%s)\1""" % "|".join(re.escape(n) for n in [*STATIC_FILES, "app.zip"])
)


def _sources() -> dict[str, bytes]:
    """Every file that goes into the site, by its path in the site."""
    files = {name: (WEB_DIR / name).read_bytes() for name in STATIC_FILES}
    files["bridge.py"] = (WEB_DIR / "bridge.py").read_bytes()
    for path in sorted((ROOT / "src").iterdir()):
        if path.suffix in (".py", ".json"):
            files[f"src/{path.name}"] = path.read_bytes()
    return files


def build_id(files: dict[str, bytes]) -> str:
    """Short hash identifying this exact set of sources."""
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + files[name] + b"\0")
    return digest.hexdigest()[:12]


def _stamp(text: str, build: str) -> str:
    text = _REFERENCE.sub(lambda m: f"{m[1]}{m[2] or ''}{m[3]}?v={build}{m[1]}", text)
    return text.replace(BUILD_PLACEHOLDER, build)


def build_site(out_dir: Path) -> Path:
    """Write the site into *out_dir*, replacing its previous contents."""
    files = _sources()
    build = build_id(files)
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    for name in STATIC_FILES:
        (out_dir / name).write_text(_stamp(files[name].decode("utf-8"), build), encoding="utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "bridge.py", files["bridge.py"].decode("utf-8").replace(BUILD_PLACEHOLDER, build)
        )
        for name, data in files.items():
            if name.startswith("src/"):
                archive.writestr(name, data)
    (out_dir / "app.zip").write_bytes(buffer.getvalue())
    return out_dir


if __name__ == "__main__":
    target = build_site(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "_site"))
    print(f"Site written to {target}")
