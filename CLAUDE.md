# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FrontierTextHandler extracts and reimports text from Monster Hunter Frontier binary game files. It reads pointer-based string tables from game data (mhfdat.bin, mhfpac.bin, mhfinf.bin), exports to CSV for translation editing, and writes modified strings back to the binary.

**Key features:**
- Automatic ECD/EXF decryption on read
- Automatic JPK/JKR decompression on read
- Optional compression and encryption on write
- No external dependencies - uses only Python standard library

## Commands

```bash
# Extract all sections defined in headers.json
python main.py --extract-all

# Extract specific data section (auto-decrypts and decompresses)
python main.py --xpath=dat/armors/legs
python main.py --xpath=dat/weapons/melee/name
python main.py --xpath=pac/skills/description

# Apply a MHFrontier-Translation release JSON to a game installation
python main.py translations-translated.json --apply-translations --lang fr --game-dir ~/mhf --compress --encrypt

# Insert translations back to binary (single section)
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin

# Insert with compression (JKR HFI)
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin --compress

# Insert with compression AND encryption (ready for game)
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin --compress --encrypt

# Decrypt a file manually
python main.py --decrypt data/mhfdat.bin output/mhfdat-decrypted.bin
python main.py --decrypt data/mhfdat.bin output/mhfdat-decrypted.bin --save-meta

# Compare strings between two files
python main.py file_a.csv --diff file_b.csv
python main.py data/mhfdat.bin --diff data/mhfdat_v2.bin --xpath=dat/armors/head

# Validate a game file's structure (encryption, compression, format)
python main.py --validate data/mhfdat.bin

# Merge translations from old CSV/JSON into freshly extracted CSV/JSON
python main.py old_translated.csv --merge new_extracted.csv
python main.py old_translated.json --merge new_extracted.json
python main.py old_translated.csv --merge new_extracted.csv output/merged.csv

# Convert ReFrontier TSV format to standard CSV
python main.py --refrontier-to-csv input.csv output.csv

# Run all tests
python -m unittest discover -v

# Show help
python main.py --help
```

## Architecture

**Data flow:**
```
Encrypted (ECD) → Decrypted → Compressed (JPK) → Decompressed → Extract strings → CSV → Edit → Reimport → Compress → Encrypt → Game-ready
```

**Key modules in `src/`:**
- `common.py` - Core parsing: reads pointer tables and decodes Shift-JIS strings (auto-decrypts and decompresses)
- `export.py` - Extracts data sections and writes CSV (UTF-8) or ReFrontier format (Shift-JIS TSV)
- `import_data.py` - Parses edited CSV and appends new strings to binary, updating pointers
- `binary_file.py` - Context manager for binary file I/O (supports in-memory data via `from_bytes()`)
- `transform.py` - Format conversion between ReFrontier and standard CSV
- `diff.py` - String comparison between two files (CSV or binary)
- `merge.py` - Translation carryover between old translated and freshly extracted files
- `crypto.py` - ECD/EXF encryption and decryption
- `jkr_decompress.py` - JPK/JKR decompression (RW, LZ, HFI, HFIRW types)
- `jkr_compress.py` - JPK/JKR compression (all 4 compression types)

**Configuration (`headers.json`):**
Defines pointer offsets for each data section. Structure: `{file_type}/{category}/{subcategory}` with:
- `begin_pointer`: Hex offset to a pointer that points to the start of the pointer table
- `entry_count`: Number of entries — plain integer or versioned map (`{"zz": 14594, "ko": 1290}`)
- Optional: `pointers_per_entry`, `null_terminated`, `entry_size`/`field_offset` for struct-strided sections

Note: `begin_pointer` is a pointer-to-pointer. The file stores an address that points to the actual table start. Use `--game-version` to select entry counts for non-ZZ versions.

## CSV Format

**Default (1.6.0+), index-keyed:**

```csv
index,source,target
0,Original Japanese,New Translation
1,Untranslated string,
```

- `index`: Stable slot number in the section's pointer table. Survives
  string-length changes that would shift raw offsets, so re-extractions
  and merges stay meaningful.
- `source`: Original text from the game binary (read-only).
- `target`: Translation. Empty on fresh extract; only non-empty rows
  are imported.
- No `location` column. The source binary and xpath are recoverable
  from the JSON `metadata` block (`source_file`, `xpath`,
  `fingerprint`) or the CSV filename (`dat-armors-head.csv` →
  `dat/armors/head`), so `--xpath` only needs to be passed explicitly
  when the filename can't carry the mapping.

**Legacy (opt-in via `--legacy-offset`), offset-keyed:**

```csv
location,source,target
0x64@mhfdat.bin,Original Japanese,New Translation
```

- `location`: Pointer offset in hex `@ filename`.
- Same semantics as the default for `source` / `target`. Use this
  format only when you need to interoperate with tooling that hasn't
  yet adopted the index form.

The importer auto-detects which format a CSV/JSON uses, so a mix of
legacy and index-keyed translations can coexist in a single project.
The ReFrontier-compatible TSV format (`export_for_refrontier`) and
`refrontier_to_csv` stay offset-keyed regardless — they operate on
pre-existing ReFrontier offsets that have no section context to
index against.

**Scope of the default flip.** Every extraction entry point emits the
new format by default: `--extract-all`, `--xpath=…`, `--quest`,
`--scenario`, `--npc`, `--ftxt`, and the matching `--quest-dir`,
`--scenario-dir`, `--npc-dir` batch modes. The standalone file
importers (`import_ftxt_from_csv`, `import_npc_dialogue_from_csv`,
`import_scenario_from_csv`, and the quest-file path through
`import_from_csv`) resolve index-keyed translations by re-extracting
the source binary and aligning positionally against live entries —
round-trips work in both formats.

The `--with-index` flag from 1.5.0 is still accepted as a silent
no-op alias so existing scripts keep working.

### Inline escapes

Two transforms run on every `target`/`source` value as it crosses the
CSV/JSON boundary. They are pure lexical, pre-decoding steps, applied
automatically by `export_as_csv` / `export_as_json` (on extract) and the
importers (on re-encode):

- **Color codes** — `‾CNN` ↔ `{cNN}` (and `‾C00` ↔ `{/c}`). The game
  encodes inline colour changes as the byte `0x7E` followed by `C` and
  two decimal digits. In Shift-JISX0213 `0x7E` decodes as `‾` (U+203E,
  overline), which is frequently mangled by tools. The brace form is
  ASCII-safe and round-trips byte-identical through the importer.
- **Grouped join marker** — `<join at="N">` → `{j}` (export only; the
  importer accepts either form). Some sections pack several pointer
  slots into one logical entry (quest tables, multi-pointer entries,
  NPC dialogue); the extractor surfaces this as a single CSV/JSON row
  separated by `{j}`. Offsets are intentionally dropped: the importer
  re-derives per-sub pointer addresses from the live pointer table by
  positional alignment, so translators never have to touch them. The
  internal representation still uses `<join at="N">` (extractors and
  `rebuild_section` need the real offsets to rewrite the pointer
  table); the rewrite happens only at the CSV/JSON export step.

Both transforms are skipped on the ReFrontier-compatible TSV path,
which continues to carry raw game bytes.

## String Encoding

Game files use Shift-JIS (specifically Shift-JISX0213). The tool handles encoding/decoding automatically.

## Binary Modification Strategy

New strings are appended to the end of the binary file and pointer values are updated to reference the new locations. This avoids size constraints of in-place replacement.

## JPK/JKR Compression

Built-in support for Monster Hunter Frontier's JPK compression format. JPK files are automatically detected and decompressed when reading game data.

**Compression types:**
- RW (0): Raw, no compression
- HFIRW (2): Huffman encoding only
- LZ (3): LZ77 compression only
- HFI (4): Huffman + LZ77 (most common)

**Public API:**
```python
from src import decompress_jkr, compress_jkr_hfi, is_jkr_file, CompressionType

# Detection and decompression
if is_jkr_file(data):
    decompressed = decompress_jkr(data)

# Compression (HFI recommended)
compressed = compress_jkr_hfi(data)
```

**File format:**
- Magic: `0x1A524B4A` ("JKR\x1A")
- 16-byte header: magic (4) + version (2) + type (2) + data_offset (4) + decompressed_size (4)
- Compressed data follows header

## ECD/EXF Encryption

Built-in support for Monster Hunter Frontier's ECD and EXF encryption formats. Encrypted files are automatically detected and decrypted when reading game data.

**Encryption types:**
- ECD (0x1A646365): Primary format, LCG-based with nibble Feistel cipher
- EXF (0x1A667865): Alternative format, 16-byte XOR key with position-dependent transform

**Key indices:** All known MHF files use key index 4 (the default). Keys 0-5 are available but rarely used.

**Public API:**
```python
from src import decrypt, encrypt, is_encrypted_file, encode_ecd, decode_ecd

# Detection and decryption
if is_encrypted_file(data):
    decrypted, header = decrypt(data)

# Encryption (uses default key 4)
encrypted = encrypt(data)

# Encryption with specific key
encrypted = encrypt(data, key_index=2)

# Re-encryption preserving original format
encrypted = encrypt(data, meta=original_header)
```

**File format:**
- ECD Magic: `0x1A646365` ("ecd\x1A")
- EXF Magic: `0x1A667865` ("exf\x1A")
- 16-byte header: magic (4) + key_index (2) + padding (2) + payload_size (4) + crc32 (4)
- Encrypted payload follows header
