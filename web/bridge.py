"""
Glue between the web page and FrontierTextHandler, run inside Pyodide.

The page writes user files into Pyodide's in-memory filesystem and calls
the functions below. Game files are decrypted and decompressed once on
load, since that is the slow step (tens of seconds for mhfdat.bin); every
later extract or build works on the decoded copy. Fingerprints are
computed on decoded bytes, so files extracted here match CLI extractions.

Nothing leaves the browser: there is no network access from this module.
"""

import gzip
import io
import json
import logging
import os
import re
import shutil
import time
import zipfile

from src import common
from src.crypto import DEFAULT_KEY_INDEX, decrypt, encrypt, is_encrypted_file
from src.export import extract_from_file
from src.import_data import (
    XPATH_PREFIX_TO_GAME_FILE,
    apply_translations_from_release_json,
    import_from_csv,
)
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
# Release JSONs parsed by stage_translations, by file name.
_releases: dict[str, dict] = {}


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

    _loaded[name] = {
        "file_type": file_type,
        "header": header,
        "encrypted": encrypted,
        "compressed": compressed,
    }
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


def _read_release(path: str) -> dict | None:
    """
    Parse a MHFrontier-Translation release, ``{lang: {xpath: [entries]}}``.

    :return: The parsed release, or None when *path* is another format
        (CSV, or a JSON extracted by this tool, which has ``metadata``
        and ``strings`` keys instead).
    """
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    for sections in data.values():
        if not isinstance(sections, dict):
            return None
        if not all(isinstance(entries, list) for entries in sections.values()):
            return None
    return data


def stage_translations(name: str, translations: list[str]) -> list[dict]:
    """
    Describe the translation files the page wrote to ``/work/translations``.

    Release files are parsed once here and kept for :func:`build`.

    :return: One item per file: ``{"name", "kind": "section"}``, or
        ``{"name", "kind": "release", "languages": {lang: n}}`` where
        *n* counts the sections that apply to the loaded game file.
    """
    file_type = _loaded[name]["file_type"]
    _releases.clear()
    staged = []
    for translation in translations:
        release = _read_release(f"{TRANSLATION_DIR}/{translation}")
        if release is None:
            staged.append({"name": translation, "kind": "section"})
            continue
        _releases[translation] = release
        languages = {
            lang: sum(1 for xpath in sections if xpath.split("/")[0] == file_type)
            for lang, sections in release.items()
        }
        staged.append({"name": translation, "kind": "release", "languages": languages})
    return staged


def _apply_release(
    name: str, translation: str, lang: str, current: str, fold: bool
) -> bool:
    """
    Apply one language of a staged release to the working copy *current*.

    The release importer works on a game folder, so this lays one out
    around the working copy, keeping only the sections for this file:
    the others would be reported as missing game files.

    :return: True if the working copy changed.
    """
    file_type = _loaded[name]["file_type"]
    sections = {
        xpath: entries
        for xpath, entries in _releases[translation].get(lang, {}).items()
        if xpath.split("/")[0] == file_type
    }
    rel_path = XPATH_PREFIX_TO_GAME_FILE.get(file_type)
    if not sections or rel_path is None:
        _reporter(f"{translation}: no '{lang}' sections for {name}.")
        return False

    game_dir = f"{WORK}/release-game"
    _reset_dir(game_dir)
    game_file = f"{game_dir}/{rel_path}"
    os.makedirs(os.path.dirname(game_file))
    shutil.copyfile(current, game_file)
    filtered = f"{WORK}/release.json"
    with open(filtered, "w", encoding="utf-8") as f:
        json.dump({lang: sections}, f, ensure_ascii=False)

    results = apply_translations_from_release_json(
        filtered, lang, game_dir,
        compress=False, encrypt=False,
        fold_unsupported_chars=fold,
    )
    if not results:
        return False
    shutil.copyfile(game_file, current)
    return True


def build(
    name: str,
    translations: list[str],
    release_languages: dict[str, str] | None = None,
    compress: bool = True,
    encrypt_output: bool = True,
    fold_unsupported_chars: bool = True,
) -> dict:
    """
    Apply staged translation files to a loaded file.

    Each translation is imported on the decoded binary in turn;
    compression and encryption run once at the end, since they are the
    slow steps.

    :param release_languages: Language to apply for each release file,
        by file name. Other files are imported as extracted CSV/JSON.
    :return: ``{"data": bytes, "applied": [...], "unchanged": [...]}``
    """
    build_dir = f"{WORK}/build"
    _reset_dir(build_dir)
    # import_from_csv reads its source by path and names nothing after
    # it, so the working copy can keep the original file name.
    current = f"{build_dir}/{name}"
    shutil.copyfile(f"{DECODED_DIR}/{name}", current)

    release_languages = release_languages or {}
    applied, unchanged = [], []
    for index, translation in enumerate(translations):
        if translation in release_languages:
            lang = release_languages[translation]
            changed = _timed(
                f"Applying {translation} ({lang})", _apply_release,
                name, translation, lang, current, fold_unsupported_chars,
            )
        else:
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
            changed = result is not None
            if changed:
                os.replace(step_output, current)
        (applied if changed else unchanged).append(translation)

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
