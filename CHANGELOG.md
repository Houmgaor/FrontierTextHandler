# Changelog

All notable changes to FrontierTextHandler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Translator-facing format spec:
[`docs/translation-format.md`](docs/translation-format.md). Pre-1.6.0
translation files import unchanged.

### Changed
- Index-keyed CSV/JSON (`index,source,target`) is the default for
  every extractor. `--legacy-offset` re-enables the pre-1.6.0
  offset-keyed shape; the 1.5.0 `--with-index` flag stays as a
  silent no-op.
- Colour codes are written as `{cNN}` / `{/c}` instead of the
  Shift-JIS `‾CNN` form. Pure bijection on round-trip.
- Grouped entries use the `{j}` marker instead of `<join at="NNN">`.
  Noise-free CSV cells, offsets re-derived positionally from the
  live pointer table on import.
- Extractors emit `{j}` directly and carry `sub_offsets: list[int]`
  per entry; `rebuild_section` reads slot addresses from there
  instead of tokenising them out of the text. `{j}` is the single
  canonical form on disk and in memory.
- `rebuild_section` applies `{j}`-form grouped translations by
  positional alignment, updating every sibling pointer. A sub-string
  count mismatch keeps the originals rather than corrupting siblings.

### Added
- **Placeholder validation** across every importer and as a new
  standalone `--validate-placeholders FILE` CLI command. Runs a
  multiset comparison of brace-form markers (`{cNN}`, `{/c}`, `{j}`,
  `{K…}`, `{i…}`, `{u…}`) between source and target on every row,
  reports dropped / added / duplicated / typoed placeholders.
  Default behaviour logs a warning summary and proceeds;
  `--strict-placeholders` turns the first mismatch into a hard
  error so CI pipelines can block bad translations before they land
  in the binary. See the *Placeholder validation* section in
  [`docs/translation-format.md`](docs/translation-format.md).

### Fixed
- `apply_translations_from_release_json`: runs `color_codes_from_csv`
  on each target before re-encoding, so `{cNN}` lands in the binary
  as `‾CNN` bytes.
- `apply_translations_from_release_json`: grouped entries now update
  every sibling pointer in both index-keyed and location-keyed
  inputs.

## [1.5.1] - 2026-04-07

### Added
- **`apply_translations_from_release_json` auto-detects gzip**: Release JSONs compressed with gzip (magic bytes `1f 8b`) are transparently decompressed before parsing. Plain JSON still works unchanged. Matches MHFrontier-Translation 0.2.0+ which ships gzip-compressed releases.
- **`apply_translations_from_release_json` accepts index-keyed entries**: Release JSON entries may now use `{"index": N, "source": ..., "target": ...}` instead of the legacy `{"location": "0xNNN@file.bin", ...}` shape. Indexed entries are resolved against the live pointer table for their xpath after the binary is decrypted/decompressed. Sections may mix both formats. The legacy `location` shape still works unchanged. Adds an optional `headers_path` parameter so the resolver can be pointed at a custom config (mainly useful for tests).

## [1.5.0] - 2026-04-06

### Added
- **`--with-index` flag (opt-in)**: Extract CSV/JSON keyed by a stable per-section `index` (slot number in the pointer table) instead of by raw byte offset. Index keys survive upstream string-length changes that would shift offsets, making re-extracted files easier to merge with existing translations. The new CSV is just three columns — `index,source,target` — with no offset/filename noise on every row; JSON records the source binary and xpath in `metadata` instead. The importer auto-detects index-keyed files and resolves indexes against the live pointer table. The legacy offset-keyed format remains the default for backward compatibility, and the ReFrontier-compatible TSV output is unchanged. Intended to become the long-term default once validated against real translation projects.
- **xpath inference for index-keyed imports**: When importing an index-keyed CSV or JSON, the section xpath is inferred from the JSON `metadata.xpath` field or from the CSV/JSON filename (e.g. `dat-armors-head.csv` → `dat/armors/head`). `--xpath` only needs to be passed explicitly to override the inference. Removes the most common "I forgot `--xpath`" footgun.
- **Binary fingerprint in index-keyed JSON metadata**: Index-keyed JSON exports now record a 16-char SHA-256 prefix of the decrypted/decompressed source binary in `metadata.fingerprint`. At import time the importer recomputes it on the target file and warns loudly on mismatch — catches the case where a translation extracted from one game version is being applied to a different version (or to a binary that already has translations applied). The warning does not abort the import. Foundation for future per-version `headers.json` support without committing to any particular versioning architecture. CSV imports skip this check (CSV stays metadata-free); use the JSON sidecar if you want fingerprint protection.
- **End-to-end roundtrip test for the new format**: extract → edit index CSV → import (with inferred xpath) → re-extract → verify translations landed at the right slots and untranslated entries are intact. Locks in the new pipeline as a whole, not just its individual pieces.
- **No-op roundtrip test**: Locks in that extracting the same binary twice yields byte-identical CSV and that importing an unedited index-keyed file does not modify the binary, so future diffs in translation repos remain meaningful.

## [1.4.0] - 2026-04-06

### Added
- **mhfgao.bin extraction**: Full Felyne partner data coverage — 2,122 strings across 16 sections
  - Armor/weapon names and descriptions (`armor_helm`, `armor_mail`, `weapon_names`, `armor_desc`, `weapon_desc`)
  - 8 personality-type dialogue templates (`dialogue_type_0` .. `dialogue_type_7`)
  - Skill descriptions + English skill names (`skill_text`, `skill_names_zenith`)
  - Situational dialogue region at 0x040 (`situational_dialogue`, 13 entries via new scan_region mode)
- **mhfsqd.bin extraction**: Squad / NPC partner data — 190 strings across 6 sections (NPC names, star ranks, skill activation/description/quest labels, header labels)
- **mhfrcc.bin extraction**: Reception / event info — 28 strings across 2 sections (7 English event titles + 7 full event descriptions, Guild Conquest title, remaining-time template via multi-field struct mode)
- **mhfmsx.bin extraction**: Mezeporta Festa — 17 item names + 17 item effects via new `literal_base` flag for struct tables without a header pointer
- **mhfpac.bin additional sections**: `text_30` and `text_48` pointer-pair tables
- **`--apply-translations` command**: Apply a MHFrontier-Translation release JSON to a full game installation in one step (`--lang fr --game-dir ~/mhf`)
- **Multi-field struct extraction**: `field_offset` in `struct_strided` mode now accepts a list (`[20,24,28,32]`) to emit multiple strings per struct row — used for mhfrcc.bin event rows that carry title + description + two placeholder slots
- **`scan_region` extraction mode**: Walks every 4-byte aligned slot in a bounded region and emits only pointers that land on a clean Shift-JIS character boundary, rejecting numeric IDs, OOB values, mid-character composition-engine fragments, decode errors, and U+FFFD replacement artefacts. Used for mixed struct regions where string pointers are interleaved with runtime substring references (mhfgao.bin 0x040 situational dialogue)
- **`literal_base` option**: `struct_strided` mode now supports a literal file-offset base (no header dereference) for tables whose base address isn't stored in a pointer slot

### Changed
- **`common.py` split**: Refactored into focused modules (`pointer_tables`, `ftxt`, `quest`, `npc`, `file_io`) with backward-compat re-exports. All existing imports from `src.common` still work.
- **`extraction_config` validation**: hex string fields in `headers.json` are now validated up front
- **`import_from_csv()`**: xpath is validated early before doing any work
- **Scenario parsing**: bounds-checking on all chunk types

### Fixed
- **`<join>` tag expansion** in the `csv-to-bin` append path
- **Empty translations JSON**: no longer crashes when the input file has zero translations

### Tests
- Test suite expanded from ~440 to **565 tests** (`test_common.py`, new `test_export.py`, new `test_import_data.py`, expanded `test_scenario.py`)

## [1.3.0] - 2026-03-02

### Added
- **Scenario file support**: Extract and reimport text from MH Frontier's 145K+ story scenario `.bin` files
  - `--scenario`: Extract text from a single scenario file (CSV + JSON output)
  - `--scenario-dir DIR`: Batch extract from a directory of scenario files (CSV + JSON output)
  - `--scenario-to-bin`: Import translations from CSV or JSON back to binary (in-place patch)
  - `--diff --scenario`: Compare strings between two scenario binary files
  - `scenario.py`: Container parser with auto-detection of sub-header vs inline chunk formats, JKR decompression for compressed chunks
  - Handles all chunk types: quest name/description (chunk0), NPC dialog with `@RETURN`/`@MYNAME`/`~C05` markers (chunk1), JKR-compressed menu/title data (chunk2)
- **Test suite**: 22 unit tests for scenario module in `tests/test_scenario.py`, including JSON round-trip

## [1.2.0] - 2026-02-23

### Added
- **`--merge` command**: Carry over translations when game binaries are updated
  - Merges an old translated CSV/JSON with a freshly extracted CSV/JSON
  - Preserves translations where source strings are unchanged
  - Flags entries where source text changed for manual review
  - Reports new, removed, and modified strings
  - Supports both CSV and JSON formats
  - `merge.py`: `MergeResult`, `merge_translations`, `write_merged_csv`, `write_merged_json`, `format_merge_report`
- **Test suite**: Tests for merge module in `tests/test_merge.py`

## [1.0.0] - 2026-02-16

### Added
- **ECD/EXF encryption support**: Full round-trip encryption and decryption for Monster Hunter Frontier's encrypted file formats
  - `crypto.py`: ECD encryption (LCG-based nibble Feistel cipher) and EXF encryption (16-byte XOR key)
  - Supports all 6 key indices (all known MHF files use key index 4)
  - Ported from ReFrontier C#
- **Automatic ECD/EXF decryption**: `read_from_pointers()` now auto-detects and decrypts encrypted files before decompression
- **CLI encryption options**: `--encrypt`, `--decrypt`, `--key-index`, `--save-meta` arguments
- **Public API exports**: `decrypt`, `encrypt`, `decode_ecd`, `encode_ecd`, `decode_exf`, `encode_exf`, `is_encrypted_file`, `CryptoError`
- **Test suite**: 50 unit tests for crypto in `tests/test_crypto.py`
- **JPK/JKR compression support**: Full round-trip compression and decompression for Monster Hunter Frontier's JPK format
  - `jkr_decompress.py`: Decompression for all 4 compression types (RW, HFIRW, LZ, HFI)
  - `jkr_compress.py`: Compression for all 4 types with Huffman and LZ77 encoding
  - Ported from MHFrontier-Blender-Addon (originally from ReFrontier C#)
- **Automatic JPK decompression**: `read_from_pointers()` now auto-detects and decompresses JPK files
- **In-memory binary handling**: `BinaryFile.from_bytes()` class method for working with decompressed data
- **Public API exports**: `decompress_jkr`, `compress_jkr`, `compress_jkr_hfi`, `compress_jkr_raw`, `is_jkr_file`, `CompressionType`
- **Test suite**: 54 unit tests for JPK codec in `tests/test_jkr.py`

### Changed
- `common.py`: Now auto-decrypts and decompresses files (decrypt → decompress pipeline)
- `import_data.py`: Added `encrypt` and `key_index` parameters to `import_from_csv()`
- `main.py`: Added CLI arguments for encryption workflow
- `binary_file.py`: Added `from_bytes()` for in-memory data support
- Updated README.md and CLAUDE.md with encryption and compression documentation

### Removed
- Dependency on ReFrontier for the complete text editing workflow (decrypt, decompress, extract, import, compress, encrypt)
