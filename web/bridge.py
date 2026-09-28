"""
Glue between the web page and FrontierTextHandler, run inside Pyodide.

The page writes user files into Pyodide's in-memory filesystem and calls
the functions below. Game files are decrypted and decompressed once on
load, since that is the slow step (tens of seconds for mhfdat.bin); every
later extract or build works on the decoded copy. Fingerprints are
computed on decoded bytes, so files extracted here match CLI extractions.

Nothing leaves the browser: there is no network access from this module.
"""

import io
import logging
import os
import re
import shutil
import time
import zipfile

from src import common
from src.crypto import DEFAULT_KEY_INDEX, decrypt, encrypt, is_encrypted_file
from src.export import extract_from_file
from src.import_data import import_from_csv
from src.jkr_compress import compress_jkr_hfi
from src.jkr_decompress import decompress_jkr, is_jkr_file

WORK = "/work"
INPUT_DIR = f"{WORK}/in"
DECODED_DIR = f"{WORK}/decoded"
TRANSLATION_DIR = f"{WORK}/translations"

# mhfdat.bin -> "dat", mhfpac-fr.bin -> "pac": the prefix selects the
# headers.json sections that apply to the file.
_FILE_TYPE_RE = re.compile(r"^mhf([a-z]{3})", re.IGNORECASE)

_reporter = print
# Per-file state from load_game_file: original header and layer flags,
# needed to rebuild a file in the same shape it was loaded in.
_loaded: dict[str, dict] = {}


class _ReporterHandler(logging.Handler):
    """Forward the tool's log records (warnings, summaries) to the page."""

    def emit(self, record: logging.LogRecord) -> None:
        _reporter(f"{record.levelname.lower()}: {record.getMessage()}")


def set_reporter(fn) -> None:
    """Route progress messages and tool logs to *fn* (a JS callback)."""
    global _reporter
    _reporter = fn
    root = logging.getLogger()
    root.handlers = [_ReporterHandler()]
    root.setLevel(logging.INFO)


def _reset_dir(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)


def _timed(label: str, fn, *args):
    _reporter(f"{label}…")
    start = time.time()
    result = fn(*args)
    _reporter(f"{label}: done in {time.time() - start:.1f} s")
    return result


def load_game_file(name: str) -> dict:
    """
    Decode ``/work/in/<name>`` once and list the sections it contains.

    :return: Summary for the page: file type, layers found, decoded size,
        and the xpaths that apply to this file.
    """
    match = _FILE_TYPE_RE.match(name)
    xpaths = common.get_all_xpaths()
    if not match:
        raise ValueError(
            f"'{name}' does not look like a game data file "
            "(expected a name such as mhfdat.bin, mhfpac.bin or mhfinf.bin)."
        )
    file_type = match.group(1).lower()
    sections = [x for x in xpaths if x.split("/")[0] == file_type]
    if not sections:
        raise ValueError(f"No text sections are known for '{name}' yet.")

    with open(f"{INPUT_DIR}/{name}", "rb") as f:
        data = f.read()

    header = None
    encrypted = is_encrypted_file(data)
    if encrypted:
        data, header = _timed("Decrypting", decrypt, data)
    compressed = is_jkr_file(data)
    if compressed:
        data = _timed("Decompressing", decompress_jkr, data)

    os.makedirs(DECODED_DIR, exist_ok=True)
    # Keep the original name: exports record it as the source file.
    with open(f"{DECODED_DIR}/{name}", "wb") as f:
        f.write(data)
    os.remove(f"{INPUT_DIR}/{name}")

    _loaded[name] = {"header": header, "encrypted": encrypted, "compressed": compressed}
    return {
        "name": name,
        "file_type": file_type,
        "encrypted": encrypted,
        "compressed": compressed,
        "decoded_size": len(data),
        "sections": sections,
    }


def extract(name: str, xpaths: list[str]) -> dict:
    """
    Extract *xpaths* from a loaded file into a zip of CSV and JSON files.

    :return: ``{"zip": bytes, "extracted": [...], "failed": [...]}``
    """
    out_dir = f"{WORK}/out"
    _reset_dir(out_dir)
    extracted, failed = [], []
    for xpath in xpaths:
        try:
            extract_from_file(
                f"{DECODED_DIR}/{name}", xpath, "", output_dir=out_dir,
            )
            extracted.append(xpath)
        except (ValueError, KeyError) as exc:
            _reporter(f"warning: {xpath} skipped: {exc}")
            failed.append(xpath)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for entry in sorted(os.listdir(out_dir)):
            archive.write(f"{out_dir}/{entry}", entry)
    _reporter(f"Extracted {len(extracted)} section(s).")
    return {"zip": buffer.getvalue(), "extracted": extracted, "failed": failed}


def build(
    name: str,
    translations: list[str],
    compress: bool = True,
    encrypt_output: bool = True,
    fold_unsupported_chars: bool = True,
) -> dict:
    """
    Apply translation files from ``/work/translations`` to a loaded file.

    Each translation is imported on the decoded binary in turn;
    compression and encryption run once at the end, since they are the
    slow steps.

    :return: ``{"data": bytes, "applied": [...], "unchanged": [...]}``
    """
    build_dir = f"{WORK}/build"
    _reset_dir(build_dir)
    # import_from_csv reads its source by path and names nothing after
    # it, so the working copy can keep the original file name.
    current = f"{build_dir}/{name}"
    shutil.copyfile(f"{DECODED_DIR}/{name}", current)

    applied, unchanged = [], []
    for index, translation in enumerate(translations):
        step_output = f"{build_dir}/step-{index}.bin"
        result = _timed(
            f"Applying {translation}",
            lambda: import_from_csv(
                f"{TRANSLATION_DIR}/{translation}",
                current,
                output_path=step_output,
                fold_unsupported_chars=fold_unsupported_chars,
            ),
        )
        if result is None:
            unchanged.append(translation)
            continue
        os.replace(step_output, current)
        applied.append(translation)

    if not applied:
        # Nothing to write: skip the slow compress and encrypt steps.
        return {"data": None, "applied": applied, "unchanged": unchanged}
    with open(current, "rb") as f:
        data = f.read()
    if compress:
        data = _timed("Compressing", compress_jkr_hfi, data)
    if encrypt_output:
        data = _timed(
            "Encrypting", encrypt, data, DEFAULT_KEY_INDEX, _loaded[name]["header"]
        )
    return {"data": data, "applied": applied, "unchanged": unchanged}
