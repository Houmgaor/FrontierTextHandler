"""
Assemble the static web interface into a folder GitHub Pages can serve.

    python web/build_site.py [OUT_DIR]      # default: _site

The Python sources run in the browser through Pyodide. They are shipped as
a single ``app.zip`` (``bridge.py`` plus the ``src`` package with
``headers.json``) so the worker downloads one file instead of one request
per module. Serve the result with ``python -m http.server -d _site``.
"""

import shutil
import sys
import zipfile
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
STATIC_FILES = ["index.html", "style.css", "app.js", "worker.js"]


def build_site(out_dir: Path) -> Path:
    """Write the site into *out_dir*, replacing its previous contents."""
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    for name in STATIC_FILES:
        shutil.copy2(WEB_DIR / name, out_dir / name)

    with zipfile.ZipFile(out_dir / "app.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(WEB_DIR / "bridge.py", "bridge.py")
        for path in sorted((ROOT / "src").iterdir()):
            if path.suffix in (".py", ".json"):
                archive.write(path, f"src/{path.name}")
    return out_dir


if __name__ == "__main__":
    target = build_site(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "_site"))
    print(f"Site written to {target}")
