# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FrontierTextHandler extracts and reimports text from Monster Hunter Frontier binary game files. It reads pointer-based string tables from decrypted game data (mhfdat.bin, mhfpac.bin, mhfinf.bin), exports to CSV for translation editing, and writes modified strings back to the binary.

## Commands

```bash
# Extract all text to output/
python main.py

# Extract specific data section
python main.py --xpath=dat/armors/legs
python main.py --xpath=dat/weapons/melee/name
python main.py --xpath=pac/skills/description

# Insert translations back to binary (creates output/mhfdat-modified.bin)
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin

# Convert ReFrontier TSV format to standard CSV
python main.py --refrontier-to-csv input.csv output.csv

# Run JPK codec tests
python -m unittest tests.test_jkr -v

# Show help
python main.py --help
```

No external dependencies - uses only Python standard library.

## Architecture

**Data flow:**
```
Decrypted binary (mhfdat.bin) → Extract strings via pointers → CSV → Edit translations → Reimport → Modified binary
```

**Key modules in `src/`:**
- `common.py` - Core parsing: reads pointer tables and decodes Shift-JIS strings (auto-decompresses JPK)
- `export.py` - Extracts data sections and writes CSV (UTF-8) or ReFrontier format (Shift-JIS TSV)
- `import_data.py` - Parses edited CSV and appends new strings to binary, updating pointers
- `binary_file.py` - Context manager for binary file I/O (supports in-memory data via `from_bytes()`)
- `transform.py` - Format conversion between ReFrontier and standard CSV
- `jkr_decompress.py` - JPK/JKR decompression (RW, LZ, HFI, HFIRW types)
- `jkr_compress.py` - JPK/JKR compression (all 4 compression types)

**Configuration (`headers.json`):**
Defines pointer offsets for each data section. Structure: `{file_type}/{category}/{subcategory}` with `begin_pointer`, `next_field_pointer`, and optional `crop_end`.

## CSV Format

```csv
location,source,target
0x64@mhfdat.bin,Original Japanese,New Translation
```

- `location`: Pointer offset in hex @ filename
- `source`: Original string (for reference)
- `target`: New string (only imported if different from source)

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
