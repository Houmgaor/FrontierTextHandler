# FrontierTextHandler

A utility to read text from Monster Hunter Frontier, edit and reinsert.
It is roughly a Python rewrite of FrontierTextTool
(from [ReFrontier](https://github.com/Houmgaor/ReFrontier), by mhvuze) in Python.

## Requirements

- **Python 3.10+** (uses modern type hints such as `list[str]`)
- No external dependencies (pure standard library)

## Install

Download the repository and run command from the main folder.
```commandline
git clone https://github.com/Houmgaor/FrontierTextHandler.git
cd FrontierTextHandler
```

## Usage

```bash
# This can save lives
python main.py --help
```

To extract the data:

1. Place game files (``mhfdat.bin``, ``mhfpac.bin``, ``mhfinf.bin``) in a ``data/`` folder.
2. Run ``main.py``.

**Note on file formats:** Game files are both **encrypted (ECD/EXF)** and **compressed (JKR)**. This tool handles both layers automatically:
- **Extraction:** Auto-decrypts ECD/EXF and auto-decompresses JKR
- **Reimport:** Use ``--compress --encrypt`` to produce game-ready files

Output data will be in ``output/*.csv``. The file ``output/refrontier.csv`` is compatible with ReFrontier.

### Extract all data

To extract all available text sections at once:

```bash
python main.py --extract-all
```

This reads `headers.json` and extracts every defined section, creating CSV and JSON files in `output/`. The tool automatically maps xpaths to their corresponding files:
- `dat/*` sections → `data/mhfdat.bin`
- `pac/*` sections → `data/mhfpac.bin`
- `inf/*` sections → `data/mhfinf.bin`

### Extract specific data

You can customize which data will be extracted.
For instance to extract only the legs armor names from mhfdat.bin:

```bash
python main.py --xpath=dat/armors/legs
```

It will create a file ``output/dat-armors-legs.csv``. A JSON file (`output/dat-armors-legs.json`) is also produced alongside the CSV.

### Change the game files

Using a CSV file, you can insert new strings (such as translations) in the original MHFrontier game.

The CSV file should follow this convention:

1. The first column (location) of the file should be the original datum location (with format [offset]@[original file name]).
2. The second column (source) is the original string value.
3. The third column (target) is the new string value.

To update the file, use `--csv-to-bin [input CSV] [output BIN file]`.
JSON files are also accepted as input. It will only add strings if "target" is different from "source".
For instance:

```commandline
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin
```

The modified file is saved to `output/mhfdat-modified.bin`.

### Compress after import

To automatically compress the modified binary using JKR HFI compression:

```bash
python main.py --csv-to-bin output/translations.csv data/mhfdat.bin --compress
```

This creates `output/mhfdat-modified.bin` with JKR compression applied. The compression log shows the size reduction achieved.

**Tip:** To produce a game-ready file in one step, add `--encrypt`:
```bash
python main.py --csv-to-bin output/translations.csv data/mhfdat.bin --compress --encrypt
```

### In-place section rebuild

When `--csv-to-bin` is combined with `--xpath`, only the target section is rewritten in the binary file. This is useful when you want to update a single section without touching the rest of the file:

```bash
python main.py --csv-to-bin output/dat-armors-legs.csv data/mhfdat.bin --xpath=dat/armors/legs
```

### Decrypt files

Decrypt an ECD/EXF-encrypted file manually:

```bash
python main.py --decrypt data/mhfdat.bin output/mhfdat-decrypted.bin
```

Use `--save-meta` to preserve the encryption header in a `.meta` file, which allows re-encryption with the original parameters later:

```bash
python main.py --decrypt data/mhfdat.bin output/mhfdat-decrypted.bin --save-meta
```

### FTXT files

Extract text from standalone FTXT text files (magic `0x000B0000`):

```bash
python main.py --ftxt data/some_ftxt_file.bin
```

### Quest files

Extract text from quest `.bin` files:

```bash
# Single quest file
python main.py --quest data/quest_file.bin

# Batch extract all quest files in a directory
python main.py --quest-dir data/quests/
```

### NPC dialogue

Extract and reimport NPC dialogue from stage dialogue binary files:

```bash
# Extract from a single file
python main.py --npc data/npc_dialogue.bin

# Batch extract from a directory
python main.py --npc-dir data/npc/

# Import translations back to binary
python main.py --npc-to-bin output/npc_dialogue.csv data/npc_dialogue.bin
```

### Validate files

Inspect the structure of a game file (encryption layer, compression layer, format):

```bash
python main.py --validate data/mhfdat.bin
```

### Compare files

Compare strings between two files. Works with CSV files and binary files:

```bash
# Compare two CSV files
python main.py file_a.csv --diff file_b.csv

# Compare two binary files (requires --xpath, --ftxt, --quest, or --npc)
python main.py data/mhfdat.bin --diff data/mhfdat_v2.bin --xpath=dat/armors/head
```

### Merge translations

Carry over translations from an old translated file into a freshly extracted file. Translations are matched by source string — if the source is unchanged, the translation is preserved:

```bash
# Merge CSV files (output written to third argument, or auto-named)
python main.py old_translated.csv --merge new_extracted.csv
python main.py old_translated.csv --merge new_extracted.csv output/merged.csv

# Also works with JSON files
python main.py old_translated.json --merge new_extracted.json
```

### Compatibility with ReFrontier

You can also convert any translation CSV to ReFrontier

```bash
python main.py --refrontier-to-csv
```

See `headers.json` for all available sections, or run `python main.py --extract-all` to extract everything at once.

## JPK Compression

FrontierTextHandler includes built-in support for JPK/JKR compression, the format used by Monster Hunter Frontier for compressed game files.

**Note:** Game files (`.bin`) have two layers: ECD encryption (outer) and JKR compression (inner). This tool handles both layers automatically.

### Automatic Decompression

JPK files are automatically detected and decompressed when reading game data. No additional steps needed.

### Python API

You can also use the compression functions directly in Python:

```python
from src import compress_jkr_hfi, decompress_jkr, is_jkr_file

# Check if a file is JPK compressed
with open("file.bin", "rb") as f:
    data = f.read()
    if is_jkr_file(data):
        decompressed = decompress_jkr(data)

# Compress data (HFI = Huffman + LZ77, most common)
compressed = compress_jkr_hfi(original_data)

# Decompress
original = decompress_jkr(compressed)
```

Supported compression types:
- **RW (0)**: Raw, no compression
- **HFIRW (2)**: Huffman encoding only
- **LZ (3)**: LZ77 compression only
- **HFI (4)**: Huffman + LZ77 (most common, best compression)

### Running Tests

```bash
python -m unittest discover -s tests -v
```

## ECD/EXF Encryption

FrontierTextHandler includes built-in support for ECD and EXF encryption, the formats used by Monster Hunter Frontier for encrypted game files.

### Automatic Decryption

Encrypted files are automatically detected and decrypted when reading game data. No additional steps needed.

### Python API

You can also use the encryption functions directly in Python:

```python
from src import decrypt, encrypt, is_encrypted_file

# Check if a file is encrypted and decrypt
with open("file.bin", "rb") as f:
    data = f.read()
    if is_encrypted_file(data):
        decrypted, header = decrypt(data)

# Encrypt data (uses default key index 4)
encrypted = encrypt(data)

# Re-encrypt preserving original format
encrypted = encrypt(data, meta=original_header)
```

Supported encryption formats:
- **ECD** (`0x1A646365`): Primary format, LCG-based with nibble Feistel cipher
- **EXF** (`0x1A667865`): Alternative format, 16-byte XOR key with position-dependent transform

All known MHF files use key index 4 (the default). Use `--key-index` to specify a different key (0–5).

## Configuration: headers.json

The `headers.json` file defines where text data is located within each binary file. Understanding this format allows you to add support for new data sections.

### Structure Overview

```json
{
  "file_type": {
    "category": {
      "subcategory": {
        "begin_pointer": "0x64",
        "next_field_pointer": "0x60",
        "crop_end": 24
      }
    }
  }
}
```

### Pointer Table Format

Monster Hunter Frontier stores text as **pointer tables** - arrays of 4-byte offsets that point to null-terminated Shift-JIS strings elsewhere in the file.

```
Binary file layout:
┌─────────────────────────────────────────────────────────┐
│ ... file header and other data ...                      │
├─────────────────────────────────────────────────────────┤
│ Pointer Table (at begin_pointer offset):                │
│   [0x1000] [0x1008] [0x1010] [0x1018] ...              │
│   (each entry is a 4-byte little-endian offset)        │
├─────────────────────────────────────────────────────────┤
│ String Data (pointed to by the table):                  │
│   0x1000: "Leather Helm\0"                              │
│   0x1008: "Iron Helm\0"                                 │
│   0x1010: "Steel Helm\0"                                │
│   ...                                                   │
└─────────────────────────────────────────────────────────┘
```

### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `begin_pointer` | Hex string | Offset to a pointer that points to the **start** of the pointer table |
| `next_field_pointer` | Hex string | Offset to a pointer that points to the **end** of the pointer table (or start of next section) |
| `crop_end` | Integer | Number of bytes to exclude from the end of the calculated range (optional, default: 0) |

**Important:** These are *pointers to pointers*. The values at `begin_pointer` and `next_field_pointer` contain the actual addresses of the pointer table boundaries.

### Understanding crop_end

The `crop_end` parameter handles cases where the pointer table contains trailing entries that shouldn't be processed:

- **Padding bytes**: Some sections have null padding at the end
- **Metadata entries**: Some tables end with non-string pointers (counts, flags, etc.)
- **Overlap prevention**: Prevents reading into the next section's data

For example, with `crop_end: 24`, the last 24 bytes (6 pointers) of the calculated range are excluded.

### Adding New Sections

To add support for a new text section:

1. **Find the pointer table** using a hex editor or [ImHex](https://imhex.werwolv.net/) with [MHF patterns](https://github.com/var-username/Monster-Hunter-Frontier-Patterns)

2. **Identify the boundaries**:
   - Find where the file stores the table's start address (`begin_pointer`)
   - Find where the file stores the table's end address (`next_field_pointer`)

3. **Add the entry** to `headers.json`:
   ```json
   "monsters": {
     "names": {
       "begin_pointer": "0x200",
       "next_field_pointer": "0x1FC",
       "crop_end": 0
     }
   }
   ```

4. **Test extraction**:
   ```bash
   python main.py --xpath=dat/monsters/names -v
   ```

5. **Verify output**: Check that strings are decoded correctly and no garbage data appears

### Example: Armor Section

The armor head names section in mhfdat.bin:

```json
"armors": {
  "head": {
    "begin_pointer": "0x64",
    "next_field_pointer": "0x60",
    "crop_end": 24
  }
}
```

This means:
- Read the 4-byte value at offset `0x64` → this gives the pointer table start
- Read the 4-byte value at offset `0x60` → this gives the pointer table end
- Subtract 24 bytes from the range to exclude trailing metadata
- Each 4-byte entry in this range is a pointer to a null-terminated armor name

### Multiline Strings

Some sections (like weapon descriptions) use **null pointer separators** (`0x00000000`) to indicate line breaks within a single logical entry. The tool automatically joins these into a single string with `<join>` markers.

## Troubleshooting

### Common Errors

#### `FileNotFoundError: 'data/mhfdat.bin' does not exist`

The input file was not found. Make sure to:
1. Create a `data/` folder in the project directory
2. Place your decrypted game files (`mhfdat.bin`, `mhfpac.bin`, etc.) in it
3. Verify the file path matches your command

#### `InterruptedError: file.csv has less than one line!`

The CSV file is empty or has no data rows. Ensure your CSV file has:
1. A header row: `location,source,target`
2. At least one data row

#### `EncodingError: Failed to encode string to Shift-JIS`

Your translation contains characters not supported by the game's encoding (Shift-JIS). Common causes:
- Emoji characters
- Special Unicode symbols
- Characters from non-Japanese/ASCII scripts

**Solution:** Replace unsupported characters with ASCII or Japanese equivalents.

#### `CSVParseError: Invalid location format`

The CSV location column is malformed. Expected format: `0x1234@filename.bin`

Check that:
1. The hex offset starts with `0x`
2. There's an `@` separator between offset and filename
3. No extra spaces or characters

#### `ValueError: Cannot find any readable data in 'file.bin' with xpath 'path'`

The xpath doesn't match the file type or the file structure is different. Solutions:
1. Verify you're using the correct xpath for your file (e.g., `dat/` for mhfdat.bin, `pac/` for mhfpac.bin)
2. Check available xpaths in `headers.json`
3. Ensure the file is a valid game file (ECD-encrypted files are auto-decrypted)

#### `JKRError: Invalid JKR magic bytes` or `JKRError: Data too short`

The file is not a valid JPK/JKR compressed file or is corrupted:
1. Verify the file is actually JPK-compressed (not all game files are)
2. Re-extract the file from the game data
3. Check if the file was partially downloaded or truncated

#### `InvalidPointerError: Pointer offset 0x... is outside file bounds`

A pointer in the file points to an invalid location. This usually means:
1. The file is corrupted or truncated
2. The wrong xpath is being used for this file type
3. The `headers.json` configuration has incorrect offsets for this game version

Try using `-v` to see which pointer is causing the issue.

### Debug Mode

Use the `-v` or `--verbose` flag to see detailed debug output:

```bash
python main.py -v data/mhfdat.bin
```

This shows:
- Number of translations found
- Pointer assignments during import
- File creation messages

## Credits

This software was realized with the support of [@ezemania2](https://github.com/ezemania2) from the 
[MezeLounge](https://discord.com/invite/monster-hunter-frontier-eu-973963573619486740) Discord community
as well as the [Mogapédia](https://mogapedia.fandom.com/fr/wiki/Monster_Hunter_Wiki), the French Monster
Hunter wiki.

## See also

- [var-username/Monster-Hunter-Frontier-Patterns](https://github.com/var-username/Monster-Hunter-Frontier-Patterns):
great reference for this project.
