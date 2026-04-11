"""
Core module functions.

Encoding utilities, configuration loading, and file I/O helpers.

Functions that were historically in this module but have been extracted
into focused submodules are re-exported here for backward compatibility:

- Pointer table reading → :mod:`src.pointer_tables`
- FTXT file parsing → :mod:`src.ftxt`
- Quest file extraction → :mod:`src.quest`
- NPC dialogue extraction → :mod:`src.npc`
"""
import codecs
import json
import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

from .binary_file import BinaryFile, InvalidPointerError
from .jkr_decompress import (
    is_jkr_file, decompress_jkr, JKRError, JKRHeader, CompressionType,
)
from .crypto import (
    is_encrypted_file, is_ecd_file, is_exf_file,
    decrypt, CryptoError, HEADER_SIZE as CRYPTO_HEADER_SIZE,
)

logger = logging.getLogger(__name__)

# Escape sequence replacements for ReFrontier format compatibility.
# Format: (standard_string, refrontier_escape)
REFRONTIER_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("\t", "<TAB>"),
    ("\r\n", "<CLINE>"),
    ("\n", "<NLINE>"),
)

# Encoding used by Monster Hunter Frontier
GAME_ENCODING = "shift_jisx0213"


# ---------------------------------------------------------------------------
# Color codes
# ---------------------------------------------------------------------------
# The game encodes inline color changes as the byte 0x7E followed by ``C`` and
# two decimal digits (e.g. ``0x7E 'C' '0' '5'``).  In shift_jisx0213, 0x7E
# decodes to U+203E OVERLINE (``‾``), which is visually confusing and often
# mangled by tools that assume plain ASCII.
#
# On disk in translation CSVs/JSONs we use an ASCII-safe brace form instead,
# matching the existing ``{K012}``/``{i131}`` keybind/icon placeholders that
# the MHFrontier-Translation project already uses:
#
#     ‾C05  →  {c05}   (open a color span)
#     ‾C00  →  {/c}    (reset to default)
#
# The mapping is a pure lexical bijection: ``color_codes_to_csv`` and
# ``color_codes_from_csv`` compose to the identity on any input, so round-
# tripping an extracted CSV through the importer reproduces the original
# byte sequence exactly.
#
# ``COLOR_CODE_KNOWN`` is informational: unknown ids still pass through with
# a warning, so newly-seen codes surface without breaking extraction.

# Color ids observed in mhfdat/mhfpac across G10+ dumps (2026-04).
COLOR_CODE_KNOWN: frozenset[int] = frozenset({
    0, 1, 2, 3, 4, 5, 6, 7, 8,
    10, 11, 14, 15, 16, 17, 18, 19, 20, 24, 28,
    69, 75,
})

_COLOR_GAME_RE = re.compile(r"‾C(\d{2})")
_COLOR_CSV_RE = re.compile(r"\{/c\}|\{c(\d{2})\}")


# ---------------------------------------------------------------------------
# Grouped-entry join marker
# ---------------------------------------------------------------------------
# Some sections (quest tables, multi-pointer entries, NPC dialogues) pack
# several pointer slots that share a common logical string into a single
# CSV/JSON row. The individual sub-strings need to be separated by a marker
# the translator can see and preserve across edits.
#
# The *internal* representation — what the extractors produce and what
# :func:`import_data.parse_joined_text` consumes — uses
# ``<join at="NNN">`` where ``NNN`` is the absolute file offset of the
# next pointer slot. That form carries real, unambiguous offsets, which
# is what ``rebuild_section`` needs to rewrite the pointer table.
#
# On disk in CSV/JSON output we rewrite the tags to the brace form
# ``{j}``. That form is:
#
#   * quote-free — so CSV writers don't wrap the field in quotes and
#     don't double each inner ``"`` into ``""`` (the pre-1.6.0 output
#     contained unreadable cells like ``<join at=""1453412"">``);
#   * offset-free — the numbers inside the tag mean nothing to
#     translators and would go stale the moment upstream strings
#     shifted. Offsets are re-derived from the live pointer table at
#     import time by positional alignment;
#   * marker-like — consistent with the ``{cNN}``/``{/c}`` colour
#     convention and not confusable with an HTML tag by diff tools.
#
# The importer understands **both** forms so existing pre-1.6.0
# translation files keep working until their maintainers regenerate
# them: ``<join at="NNN">`` is the canonical internal form, ``{j}`` is
# the on-disk form, and either may appear in a translation file.
JOIN_MARKER = "{j}"

# Matches either the new ``{j}`` marker or the legacy ``<join at="NNN">``
# form. Used to split a grouped entry into its sub-strings; callers that
# also need the per-sub ptr offset must look them up against a freshly-
# extracted live entry (see ``import_data.parse_joined_text``).
_JOIN_SPLIT_RE = re.compile(r'\{j\}|<join at="\d+">')

# Matches only the internal ``<join at="NNN">`` tag form — used by
# :func:`join_codes_to_csv` to rewrite the extractor's output to the
# on-disk ``{j}`` marker.
_JOIN_TAG_RE = re.compile(r'<join at="\d+">')


def join_codes_to_csv(text: str) -> str:
    """
    Rewrite internal ``<join at="NNN">`` tags to the CSV/JSON ``{j}``
    marker form.

    The extractors produce the tag form with real ptr offsets embedded;
    the offsets are discarded on the way to disk because they are
    re-derived from the live pointer table at import time. This makes
    extracted files portable across re-extractions and immune to CSV
    quote-escaping noise.

    :param text: Extracted game string possibly containing ``<join>`` tags
    :return: Same text with ``<join>`` tags rewritten to ``{j}``
    """
    return _JOIN_TAG_RE.sub(JOIN_MARKER, text)


def color_codes_to_csv(text: str) -> str:
    """
    Rewrite game-form color codes (``‾CNN``) to the CSV brace form.

    ``‾C00`` becomes ``{/c}`` (close/reset); every other ``‾CNN`` becomes
    ``{cNN}``.  Unknown ids are passed through with a warning.

    :param text: Decoded game string possibly containing ``‾CNN`` codes
    :return: Same text with color codes rewritten
    """
    def repl(m: "re.Match[str]") -> str:
        nn = m.group(1)
        if nn == "00":
            return "{/c}"
        try:
            if int(nn) not in COLOR_CODE_KNOWN:
                logger.warning(
                    "Unknown color code ‾C%s in extracted text; passing through", nn
                )
        except ValueError:
            pass
        return "{c" + nn + "}"

    return _COLOR_GAME_RE.sub(repl, text)


def color_codes_from_csv(text: str) -> str:
    """
    Inverse of :func:`color_codes_to_csv`: rewrite ``{cNN}``/``{/c}`` back
    to the game's ``‾CNN`` form before re-encoding to Shift-JIS.

    :param text: Translation string using the CSV brace form
    :return: Same text with color codes rewritten to game form
    """
    def repl(m: "re.Match[str]") -> str:
        if m.group(0) == "{/c}":
            return "‾C00"
        nn = m.group(1)
        try:
            if int(nn) not in COLOR_CODE_KNOWN:
                logger.warning(
                    "Unknown color code {c%s} in translation input; passing through",
                    nn,
                )
        except ValueError:
            pass
        return "‾C" + nn

    return _COLOR_CSV_RE.sub(repl, text)


class EncodingError(ValueError):
    """Raised when encoding or decoding fails for game text."""
    pass


def decode_game_string(
    data: bytes,
    errors: str = "replace",
    context: Optional[str] = None
) -> str:
    """
    Decode a byte string from the game's encoding (Shift-JIS).

    :param data: Raw bytes to decode
    :param errors: Error handling mode ('strict', 'replace', 'ignore')
    :param context: Optional context string for error messages (e.g., offset)
    :return: Decoded string
    :raises EncodingError: If errors='strict' and decoding fails
    """
    try:
        return codecs.decode(data, GAME_ENCODING, errors=errors)
    except (UnicodeDecodeError, LookupError) as exc:
        ctx = f" at {context}" if context else ""
        raise EncodingError(
            f"Failed to decode Shift-JIS string{ctx}: {exc}"
        ) from exc


def encode_game_string(
    text: str,
    errors: str = "strict",
    context: Optional[str] = None
) -> bytes:
    """
    Encode a string to the game's encoding (Shift-JIS).

    :param text: String to encode
    :param errors: Error handling mode ('strict', 'replace', 'ignore', 'xmlcharrefreplace')
    :param context: Optional context string for error messages
    :return: Encoded bytes
    :raises EncodingError: If errors='strict' and encoding fails
    """
    try:
        return codecs.encode(text, GAME_ENCODING, errors=errors)
    except (UnicodeEncodeError, LookupError) as exc:
        ctx = f" for {context}" if context else ""
        raise EncodingError(
            f"Failed to encode string to Shift-JIS{ctx}: {exc}. "
            f"String contains characters not representable in Shift-JIS."
        ) from exc


def skip_csv_header(reader: Iterator[list[str]], input_file: str) -> None:
    """
    Skip the header row of a CSV reader.

    :param reader: CSV reader object
    :param input_file: Input file path (for error messages)
    :raises InterruptedError: If the file has less than one line
    """
    try:
        next(reader)
    except StopIteration as exc:
        raise InterruptedError(f"{input_file} has less than one line!") from exc


DEFAULT_HEADERS_PATH = "headers.json"


def _is_extraction_leaf(value: dict) -> bool:
    """
    Check if a headers.json node is a leaf extraction config.

    Leaf nodes must have ``begin_pointer`` plus one of these mode indicators:

    - Standard pointer-pair: ``next_field_pointer``
    - Count-based pointer table: ``count_pointer``
    - Struct-strided fields: ``entry_count`` + ``entry_size`` + ``field_offset``
    - Indirect count (flat or strided): ``count_base_pointer`` + ``count_offset``
    - Null-terminated: ``null_terminated``
    - Null-terminated grouped: ``null_terminated`` + ``grouped_entries``
    - Quest table: ``quest_table``
    """
    if "begin_pointer" not in value:
        return False
    return (
        "next_field_pointer" in value
        or "count_pointer" in value
        or "entry_count" in value
        or "count_base_pointer" in value
        or value.get("null_terminated") is True
        or value.get("quest_table") is True
    )


def get_all_xpaths(headers_path: str = DEFAULT_HEADERS_PATH) -> list[str]:
    """
    Get all valid xpaths from the headers configuration.

    Recursively traverses the headers.json structure to find all
    leaf nodes with extraction configurations.

    :param headers_path: Path to the headers.json configuration file.
    :return: List of xpath strings (e.g., ["dat/armors/head", "dat/weapons/melee/name"])
    """
    with open(headers_path, encoding="utf-8") as f:
        data = json.load(f)

    xpaths = []

    def traverse(obj: dict, path: list[str]) -> None:
        """Recursively traverse to find leaf nodes with pointer data."""
        for key, value in obj.items():
            # Skip comment fields
            if key.startswith("_"):
                continue
            if not isinstance(value, dict):
                continue
            # Check if this is a leaf node with extraction config
            if _is_extraction_leaf(value):
                xpaths.append("/".join(path + [key]))
            else:
                # Recurse into nested structure
                traverse(value, path + [key])

    traverse(data, [])
    return sorted(xpaths)


def read_json_data(
    xpath: str = "dat/armor/head",
    headers_path: str = DEFAULT_HEADERS_PATH
) -> tuple[int, int, int]:
    """
    Read data from a JSON file.

    :param xpath: Data path as an XPATH.
        For instance, "dat/armor/head" to get 'headers.json'["dat"]["armors"]["head"].
    :param headers_path: Path to the headers.json configuration file.
    :return: Begin pointer, end pointer and crop before end
    """
    path = xpath.split("/")
    with open(headers_path, encoding="utf-8") as f:
        data = json.load(f)
        pointers = data
        for part in path:
            pointers = pointers[part]
        if "begin_pointer" not in pointers or "next_field_pointer" not in pointers:
            raise ValueError(
                "Please specify more precise path. Options are: '" +
                ",".join(pointers.keys()) + "'."
            )
        crop_end = 0
        if "crop_end" in pointers:
            crop_end = pointers["crop_end"]
        return (
            int(pointers["begin_pointer"], 16),
            int(pointers["next_field_pointer"], 16),
            crop_end,
        )


def compute_binary_fingerprint(file_data: bytes) -> str:
    """
    Compute a stable fingerprint for a decrypted/decompressed game binary.

    Used to detect when a translation file extracted from one binary is
    being applied to a different one (different game version, different
    patch level, or a binary that already has translations applied).

    The fingerprint is the SHA-256 of the supplied bytes, truncated to
    16 hex characters (64 bits — collision-resistant enough for the
    handful of binaries the project tracks, short enough to be readable
    in JSON metadata and log lines).

    Pass *decrypted, decompressed* bytes — the raw on-disk file changes
    on every re-encryption due to ECD's randomized key stream, so
    fingerprinting the encrypted form would be useless.

    :param file_data: Decrypted, decompressed binary contents
    :return: 16-character hex fingerprint
    """
    import hashlib
    return hashlib.sha256(file_data).hexdigest()[:16]


def load_file_data(file_path: str) -> bytes:
    """
    Load a game file, auto-decrypting and decompressing as needed.

    :param file_path: Path to the game file
    :return: Raw binary data ready for parsing
    """
    with open(file_path, "rb") as f:
        file_data = f.read()

    if is_encrypted_file(file_data):
        try:
            file_data, _ = decrypt(file_data)
        except CryptoError as exc:
            raise CryptoError(f"Failed to decrypt '{file_path}': {exc}") from exc

    if is_jkr_file(file_data):
        try:
            file_data = decompress_jkr(file_data)
        except JKRError as exc:
            raise JKRError(f"Failed to decompress '{file_path}': {exc}") from exc

    return file_data


def read_extraction_config(
    xpath: str,
    headers_path: str = DEFAULT_HEADERS_PATH
) -> dict:
    """
    Read the extraction configuration for a given xpath.

    Returns the raw dict from headers.json for the given xpath leaf node.

    :param xpath: Data path (e.g., "jmp/menu/title")
    :param headers_path: Path to the headers.json configuration file
    :return: Config dict with extraction parameters
    :raises ValueError: If the xpath doesn't point to a valid leaf node
    :raises KeyError: If the xpath path doesn't exist
    """
    path = xpath.split("/")
    with open(headers_path, encoding="utf-8") as f:
        data = json.load(f)
    node = data
    try:
        for part in path:
            node = node[part]
    except KeyError as exc:
        raise KeyError(
            f"xpath '{xpath}' not found in {headers_path}: "
            f"key {exc} does not exist at path '{'/'.join(path[:path.index(str(exc.args[0]))])}'"
        ) from exc
    if not isinstance(node, dict) or not _is_extraction_leaf(node):
        available = ",".join(k for k in node.keys() if not k.startswith("_")) if isinstance(node, dict) else str(type(node).__name__)
        raise ValueError(
            f"xpath '{xpath}' is not a valid extraction leaf in {headers_path}. "
            f"Options are: '{available}'."
        )
    # Validate required key
    if "begin_pointer" not in node:
        raise ValueError(
            f"xpath '{xpath}' is missing required key 'begin_pointer' in {headers_path}."
        )
    # Validate hex string fields
    _validate_config_hex_fields(node, xpath, headers_path)
    return node


def _validate_config_hex_fields(node: dict, xpath: str, headers_path: str) -> None:
    """
    Validate that hex string fields in an extraction config are well-formed.

    :param node: Extraction config dict
    :param xpath: xpath for error messages
    :param headers_path: headers.json path for error messages
    :raises ValueError: If any hex field is malformed
    """
    hex_fields = [
        "begin_pointer", "next_field_pointer", "count_pointer",
        "count_base_pointer", "count_offset", "quest_text_offset",
    ]
    for field_name in hex_fields:
        if field_name not in node:
            continue
        value = node[field_name]
        if not isinstance(value, str):
            raise ValueError(
                f"xpath '{xpath}' field '{field_name}' must be a hex string, "
                f"got {type(value).__name__}: {value!r} (in {headers_path})"
            )
        try:
            int(value, 16)
        except ValueError:
            raise ValueError(
                f"xpath '{xpath}' field '{field_name}' is not a valid hex string: "
                f"{value!r} (in {headers_path})"
            )


@dataclass
class ValidationResult:
    """Result of validating a game file."""
    file_path: str
    file_size: int
    layers: list[str] = field(default_factory=list)
    inner_format: str = "Raw binary data"
    valid: bool = True
    error: Optional[str] = None


def validate_file(file_path: str) -> ValidationResult:
    """
    Validate a game file and report its structure.

    Detects encryption (ECD/EXF), compression (JKR), and inner format
    (FTXT or raw binary), attempting to decode each layer.

    :param file_path: Path to the file to validate
    :return: ValidationResult with layer info and validity status
    """
    import os
    from .ftxt import is_ftxt_file, FTXT_HEADER_SIZE

    if not os.path.exists(file_path):
        return ValidationResult(
            file_path=file_path, file_size=0,
            valid=False, error=f"File not found: {file_path}",
        )

    with open(file_path, "rb") as f:
        data = f.read()

    result = ValidationResult(file_path=file_path, file_size=len(data))

    if len(data) == 0:
        result.valid = False
        result.error = "File is empty"
        return result

    # Layer 1: Encryption
    if is_encrypted_file(data):
        if is_ecd_file(data):
            enc_type = "ECD"
        else:
            enc_type = "EXF"

        key_index = struct.unpack_from("<H", data, 4)[0] if len(data) >= 6 else 0
        result.layers.append(f"{enc_type} encrypted (key index {key_index})")

        try:
            data, _ = decrypt(data)
        except CryptoError as exc:
            result.valid = False
            result.error = f"{enc_type} decryption failed: {exc}"
            return result

    # Layer 2: Compression
    if is_jkr_file(data):
        header = JKRHeader.from_bytes(data)
        if header is not None:
            try:
                comp_name = CompressionType(header.compression_type).name
            except ValueError:
                comp_name = f"type {header.compression_type}"
            result.layers.append(
                f"JKR compressed ({comp_name}, "
                f"decompressed: {header.decompressed_size:,} bytes)"
            )
        else:
            result.layers.append("JKR compressed (unknown)")

        try:
            data = decompress_jkr(data)
        except JKRError as exc:
            result.valid = False
            result.error = f"JKR decompression failed: {exc}"
            return result

    # Inner format detection
    if is_ftxt_file(data):
        if len(data) >= FTXT_HEADER_SIZE:
            string_count = struct.unpack_from("<H", data, 0x0A)[0]
            result.inner_format = f"FTXT ({string_count} strings)"
        else:
            result.inner_format = "FTXT (truncated header)"
    else:
        result.inner_format = "Raw binary data"

    return result


# ---------------------------------------------------------------------------
# Backward-compatible re-exports from extracted submodules.
# All names that were previously defined in this file remain importable from
# ``src.common`` so that existing ``from .common import X`` statements in
# the rest of the codebase continue to work.
# ---------------------------------------------------------------------------

from .pointer_tables import (  # noqa: E402, F401
    read_until_null,
    read_next_string,
    read_file_section,
    read_from_pointers,
    read_multi_pointer_entries,
    read_struct_strings,
    read_quest_table,
    _read_indirect_count,
    extract_text_data,
    extract_text_data_from_bytes,
)

from .ftxt import (  # noqa: E402, F401
    FTXT_MAGIC,
    FTXT_HEADER_SIZE,
    is_ftxt_file,
    extract_ftxt,
    extract_ftxt_data,
)

from .quest import (  # noqa: E402, F401
    QUEST_TEXT_LABELS,
    split_join_text,
    extract_quest_file,
    extract_quest_file_data,
)

from .npc import (  # noqa: E402, F401
    extract_npc_dialogue,
    extract_npc_dialogue_data,
)
