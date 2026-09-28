# Changelog

All notable changes to FrontierTextHandler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Web interface: sections grouped by folder, and search across them.**
  The editor menu and the file list group sections by folder (`pac`,
  `pac/skills`, `dat/goocoo/accessory_1`, …) and sort `text_<offset>`
  tables by offset. Typing in the editor's search box also lists the other
  sections whose original text or translation contains it; one click opens
  a section, filtered. A file list heading selects or clears its group.
- **829 `mhfpac.bin` UI text tables** (`pac/text_<offset>`, 23,099 rows): menus,
  help pages, event and guild screens, messages. They are the flat string
  lists of the file header, mapped by the new `tools/map_pac_tables.py`,
  which checks each table against other clients and existing sections.
  It also maps 30 tables that are lists of null-terminated string lists
  (3,957 strings, one row per list), read with a new `null_terminated`
  option for `record_levels` levels.
- **The rest of the `mhfpac.bin` text** (91 more sections, ~3,000 rows):
  - Hand-mapped trees: the Hunter Navi goals (`pac/hunter_navi/…`,
    14 chapters, 164 steps with their summaries and pages), event and
    minigame help (`pac/help/…`), counter guides (`pac/guide/…`), unlock
    notices (`pac/unlock_notice/…`, 181), magazine articles
    (`pac/article/…`, 93), short NPC scenes (`pac/scene_dialogue`, 579
    scenes, 220 of them distinct) and town descriptions (`pac/town_info`).
  - From `tools/map_pac_tables.py`: 55 record tables (NPC dialogue such
    as the caravan balloon crew, one string field per record) and 16 more
    lists of lists, whose index may point anywhere in the file.

  Uncovered pac text goes from about a third of the file's characters
  (~5,600 strings) to 1.6% (~820 strings, mostly single labels).
- **The rest of the `mhfdat.bin` text**: a quiz (`dat/quiz/…`, 290
  questions with their answers), Caravan routes (`dat/caravan_route/…`,
  279 routes with their destinations and objectives), the dojo drill
  briefings (`dat/dojo_briefing`), party search purposes and preset
  comments (`dat/party_search/…`) and secret area descriptions
  (`dat/secret_area/…`). What remains unextracted is 13 tutorial page
  lists that nothing in the file points to (older drafts) and a few labels.
- **More `mhfpac.bin` text:** village and forge requests, guild cooking
  recipes, key configuration labels and key names (hand-mapped), and 19
  more flat tables from `tools/map_pac_tables.py` (furniture prompts,
  option values, hunting contest labels, shop prompts). `pac/menu/smith`
  now covers its whole table (155 rows; rows 0-21 are unchanged).
- **`mhfmfd.bin` support** (`mfd/partnyaa_commentary`): the 37 announcer
  lines of the Partnyaa race minigame, never translated in the English
  client.
- **`record_levels` options:** a `null_terminated` level of records wider
  than 4 bytes ends at the first all-zero record; `skip_entries` leaves top
  records whose lists another section reads. List pointers that are 0 or
  not 4-byte aligned (flag values) are skipped, and a pointer slot reached
  twice is read only the first time, so no slot is in two rows. A level
  can end at the first record whose u32 at `end_offset` is 0, take a fixed
  `count`, or be `inline` (records inside the parent, such as a quiz
  question's answers).
- **Goocoo text** (`dat/goocoo/…`, 22 sections, 899 strings): accessory
  and garden names and descriptions, personalities, interactions and food
  descriptions. The English client never translated these.
- **Tip pages** (`dat/tips/…`): hunter basics and the two dojo rule sets
  (68 pages), the instructor's tutorial tips (220 titles, 1,164 pages) and
  the hunter's guide (4 chapters, 58 sections, 167 pages).
- **`record_levels` extraction mode** for records that point to lists of
  records (a tip and its pages, a guide chapter and its sections). Rows are
  one per list, joined with `{j}`, and import like any grouped entry.
- **Caravan skills** (`pac/skills/caravan/name`, `pac/skills/caravan/description`):
  109 skill names and their descriptions (狩人珠スキル, "Caravan Gem" skills
  in the English client), from header `0xA24` and `0xACC`.

### Fixed
- **Standalone quest files had no text** (`--quest`, `--quest-dir`, quest
  import and diff). The quest text pointer (`QuestStringsPtr`) was read at
  `+0xE8` in the main quest properties instead of `+0x28`, so every real
  quest file failed with "No text found in quest file". All 54,977 quest
  files of Erupe's `bin/quests` now extract except six that have no text
  block (quests 64551 and 64552), which now say so.
- **Skill lists have one skill per row.** `pac/skills/name`, `pac/skills/effect`
  and `pac/skills/effect_z` each came out as a single row joining every name
  with `{j}` (225, 535 and 53 parts): a null pointer anywhere in a flat table
  made nulls act as group separators, and these tables are padded with
  nulls. The new `null_padding` option in `headers.json` keeps one row per
  pointer; the padding stays in place on import. Files extracted from these
  three sections should be extracted again.
- **`sqd/npc_names` no longer repeats the star labels.** It read 43 entries;
  the last 3 are `sqd/star_rank`'s ★/★★/★★★, so a translation in either
  section also changed the other. It now stops at 40, where the file header
  says `star_rank` starts.
- **`rcc/events_en` extracts all 8 labels.** The file stores the count (8)
  next to the table pointer; FTH read 7 and missed the last one.

### Removed
- **`pac/skills/description`** and **`gao/situational_dialogue`**, which were
  not text. Header `0xB8` in `mhfpac.bin` is an array of small-integer structs,
  and `0x40` in `mhfgao.bin` a mixed data region; both were read as pointers
  and produced fragments starting mid-string or binary garbage (U+FFFD).
  Importing any translation into `pac/skills/description` failed, since the
  garbage cannot be re-encoded. The real Felyne lines that
  `situational_dialogue` reached are extracted by `gao/dialogue_type_*` and
  `gao/skill_text`. Translation files for these two sections should be
  deleted.

## [1.9.0] - 2026-09-28

### Performance
Output is byte-identical to 1.8.0 throughout (checked against frozen copies
of the old codecs, and on real game files). Timings on `mhfdat.bin`
(7 MB encrypted, 31 MB decoded), CPython / browser:

| Step | Before | After |
|---|---|---|
| Decrypt (ECD) | 7.1 s / 15 s | 0.3 s / 0.5 s |
| Decompress (HFI) | 15.6 s / 34 s | 1.8 s / 3.3 s |
| Compress (HFI) | 27.8 s / 53 s | 17 s / 38 s |
| Encrypt (ECD) | 7.5 s / 15 s | 0.3 s / 0.4 s |
| `--extract-all` (dat, pac, inf) | 470 s | 4.5 s |

- **ECD** is computed on whole buffers: its 8 nibble rounds are linear, so
  each byte is a table lookup XOR a keystream byte (22-34x faster).
- **JKR decompression** decodes Huffman a byte at a time from cached tree
  transitions instead of seeking and reading per bit, and LZ copies use
  slices (9x on HFI files).
- **JKR compression** keeps the same match search with cheaper bookkeeping
  (1.6x). Huffman-only compression is 13x faster.
- **`--extract-all`** decrypts and decompresses each game file once instead
  of once per section, and strings are read with one scan instead of byte
  by byte. JSON exports are written without the json module's slow indented
  encoder (same text).

### Added
- **Translate in the page.** Step 2 of the web interface has an editor:
  pick a section, type translations beside the originals, with search,
  filters and live checks (lost or extra `{cNN}`/`{j}` markers, lines
  longer than the game's text box, characters that will be replaced or
  cannot be shown). Work is saved in the browser, can be downloaded as the
  standard JSON files, and is included when building. Translation files
  and releases can be opened in the editor to continue from them; this
  never overwrites rows already translated there.
- **Web interface** (`web/`, deployed to GitHub Pages): extract text and
  build game-ready files in the browser, with no installation. The tool
  runs locally through Pyodide in a Web Worker; game files never leave
  the browser. Available in English and French, and accepts
  MHFrontier-Translation releases (`translations-<lang>.json.gz`) as
  well as extracted CSV/JSON files.

### Fixed
- **Grouped pac tables extract as groups again.** Since 1.6.0, the 11
  `mhfpac.bin` tables marked `grouped_entries` that also carry an
  `entry_count` (`pac/text_14` to `pac/text_54`) came out one row per
  pointer, e.g. 100 rows instead of 50 name/description pairs for
  `pac/text_50`. Translations made in the grouped form could no longer be
  imported: `--csv-to-bin` stopped with "grouped entry has 2 sub-strings
  but the live section has 1", and `--apply-translations` skipped them
  with a warning (97 French control-binding strings). Files extracted
  with 1.6.0–1.8.0 from these tables should be extracted again.
- **Web interface: no more broken page right after a deploy.** Browsers
  may cache each file for 10 minutes, so a new page could run with an old
  worker ("commands[command] is not a function"). The build now versions
  every reference between the site's files, and the page checks that the
  worker and Python bridge come from its own build, asking for a reload
  otherwise.
- Truncated JKR files now raise `JKRError`. Type 2 (HFIRW) crashed with a
  bare `IndexError`, and type 4 (HFI) with a cut-off Huffman table silently
  decompressed to zeros.
- **`--apply-translations` honours `--fold-unsupported-chars`.** It was
  the one importer 1.8.0 missed, so any release with accented text (the
  French one, for instance) failed with an `EncodingError`.
- **No false placeholder warnings on per-language releases.**
  `translations-<lang>.json.gz` entries carry no `source`, so every
  colour code was reported as an extra placeholder (14,371 warnings for
  the French release). Entries without a source are no longer checked.
- The per-pointer "Assigned value" log line is now debug-level; applying
  a large release printed one line per string.
- **`pip install` works.** The build failed under setuptools 77+ (a
  license classifier alongside a PEP 639 license expression), and the
  `frontier-text-handler` entry point called `main()` without arguments.
- **`headers.json` is found from any working directory.** It moved to
  `src/headers.json`, ships as package data, and `DEFAULT_HEADERS_PATH`
  is resolved relative to the package instead of the current folder.

### Changed
- **Python 3.11+ required.** `requires-python` goes from 3.7 (never true:
  the code uses PEP 604 `X | Y` annotations) to 3.11, as 3.10 reaches
  end of life in October 2026. CI now tests 3.11–3.14.
- CI: `actions/checkout` and `actions/setup-python` bumped to v7, and a
  job step installs the package and runs it from outside the repository.
- Docs updated for CP932: the colour-code prefix `0x7E` now decodes as
  `~`, not `‾`.

## [1.8.0] - 2026-09-18

### Fixed
- **Game encoding is CP932, not `shift_jisx0213`.** MHF is a Japanese Windows
  title, so its text is Windows-31J. The two codecs agree on ordinary kana and
  kanji but diverge in the NEC-selected IBM-extended area, which is where the
  game keeps its Roman numerals:

  | bytes | CP932 (correct) | `shift_jisx0213` (previous) |
  |---|---|---|
  | `0xFA4A`–`0xFA53` | Ⅰ Ⅱ Ⅲ Ⅳ Ⅴ Ⅵ Ⅶ Ⅷ Ⅸ Ⅹ | 貤 賖 賕 賙 𧶠 賰 賱 𧸐 贉 贎 |

  A weapon called `ダガダイアⅡ` extracted as `ダガダイア賖`, 6092 occurrences
  across the corpus, plus `〜` (U+301C) for `～` (U+FF5E) and `−` (U+2212) for
  `－` (U+FF0D). Verified against 238289 extracted strings: CP932 decodes
  every one, and changes 7380 characters, all corrections.

  This never corrupted a binary — the mis-decoded characters re-encoded to
  the same bytes — but extracted text was wrong on screen and could not be
  searched. **Translation CSVs produced before this release must be migrated**;
  the affected characters have no CP932 encoding and will fail on import.

### Changed
- **Accented Latin now raises instead of being silently mangled.** `é` is not
  CP932-representable. Under `shift_jisx0213` it encoded to `0x85 0x7E`, whose
  trailing byte is the game's colour-code prefix — bytes MHF reads as garbage.
  Callers writing non-Japanese text must pass `--fold-unsupported-chars`,
  which was already the intended path.
- **`--fold-unsupported-chars` now works on every importer.** It was wired
  only into `--csv-to-bin`, so `--ftxt-to-bin`, `--scenario-to-bin` and
  `--npc-to-bin` had no way to handle accented text. That was survivable while
  the wrong codec silently encoded `é` to garbage bytes; with CP932 correctly
  refusing it, those three paths would have had no route at all for European
  translations. Scenario and NPC dialogue are exactly what gets translated.
- `COLOR_PREFIX` is derived from `GAME_ENCODING` rather than hard-coded, since
  what `0x7E` decodes to depends on the codec (`~` under CP932, `‾` under
  `shift_jisx0213`). Hard-coding it is what coupled the colour-code layer to a
  single encoding.

### Note
- Encoding a Roman numeral is not byte-identical to a `0xFA4A`-form original:
  CP932 has two byte pairs per numeral and encoding picks the `0x8754` form.
  Both appear in the shipped game (6124 and 85 occurrences respectively), the
  glyph is the same, and the length is unchanged, so pointer tables are
  unaffected. Only rows a translator rewrote are re-encoded at all.

## [1.7.0] - 2026-07-01

### Added
- **`pac/menu/*` section mappings** for the town/box UI string tables:
  `pac/menu/item_box`, `pac/menu/change_equip`, `pac/menu/smith`, and
  `pac/menu/options` (item box, equipment-change, blacksmith, and
  options menus). Translation files for these sections **require this
  release or newer** — older builds raise `KeyError: 'menu'` on import
  because their `headers.json` predates the mapping.

### Changed
- **ReFrontier TSV is now opt-in.** The legacy
  `output/refrontier.csv` (Shift-JIS TSV with `Offset/Hash/JString`)
  was emitted by every single-file extractor (`--xpath`, `--ftxt`,
  `--quest`, `--npc`, `--scenario`, `--extract-all`) regardless of
  whether anyone consumed it. It is now off by default; pass
  `--refrontier-tsv` to opt back in. Programmatic callers of
  `extract_from_file` / `extract_*_file` / `extract_all` can pass
  `refrontier_tsv=True` for the same effect; the returned
  `refrontier_path` is an empty string when the flag is off.
  Modern UTF-8 CSV/JSON outputs cover every round-trip the importer
  needs.

### Fixed
- **Scenario import handles JKR-compressed chunks.** Scenario files
  with a JKR-compressed chunk1 (NPC dialog) or chunk2 (menu/title)
  crashed `--scenario-to-bin` with `IndexError: bytearray index out of
  range`: those chunks are extracted from a decompressed buffer, so
  string offsets pointed past the end of the still-compressed file. The
  container is now rebuilt chunk by chunk — uncompressed chunks patched
  in place, JKR chunks decompressed, patched, recompressed with the
  original compression type, and their size headers rewritten. Malformed
  or oversized chunk tables copy through unchanged instead of crashing.
  (Refs #5)
- **Clearer error when a translation file's section is unknown to the
  installed `headers.json`.** Importing a file whose `metadata.xpath`
  (or filename) resolves to a section this build doesn't define now
  raises a `KeyError` that hints the section may be newer than the
  installed FrontierTextHandler and to update, instead of a bare
  `KeyError: '<segment>'`.
- `--npc` no longer crashes on stage dialogue files containing bytes
  that decoded through `\ufffd` placeholders (issue #4). The strict
  Shift-JIS re-encode in `export_for_refrontier` was the only failing
  path; it is no longer in the default extraction pipeline.
- `--npc` now validates the NPC table and per-block structure and
  raises a clear `ValueError` ("input is likely not an NPC dialogue
  file") instead of producing hundreds of garbage rows when run on
  the wrong file type (e.g. a stage geometry `.pac`). The format has
  no magic bytes, so the previous parser walked into random data
  until it coincidentally hit a `(0xFFFFFFFF, 0xFFFFFFFF)`
  pseudo-terminator. Caps: ≤10000 NPCs per file, ≤1024 dialogues per
  NPC, header_size must be a multiple of 4 within file bounds. Issue
  #4's `st200-hd.pac` reproducer was a stage geometry file, not a
  dialogue file — it now fails loudly at the table walk.

## [1.6.0] - 2026-04-12

Translator-facing format spec:
[`docs/translation-format.md`](docs/translation-format.md). Pre-1.6.0
translation files import unchanged.

### Changed
- **`headers.json` config simplified**: Replaced `next_field_pointer` +
  `crop_end`, `count_base_pointer` + `count_offset` + `count_type`,
  and `count_pointer` with a single `entry_count` field per section.
  Removes 6 config keys and the fragile pointer-borrowing hack where
  adjacent sections shared boundary pointers with manual byte trimming.
  Legacy config formats are still accepted during transition.
- **Empty `target` for untranslated rows**: Fresh extracts leave the
  `target` column empty instead of duplicating `source`. Halves file
  size and makes translation progress visible at a glance. The
  importer skips rows where `target` is empty; pre-1.6.0 files that
  use `target == source` for untranslated rows still import correctly.
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
- **Line-length validation** for translations via `--validate-line-lengths`
  and `--measure-line-lengths` CLI commands. Measures the maximum
  display width and sub-string count of each section from the original
  Japanese binaries, stores limits in `headers.json`
  (`max_display_width`, `max_sub_count`), and validates translations
  against those limits. Uses Unicode East Asian Width (CJK = 2 cells,
  ASCII = 1), strips inline placeholders before measurement.
  `--max-expansion N` applies a margin multiplier (default 1.0).
  `--strict-line-lengths` turns violations into hard errors for CI.
- **Multi-version game support** via `--game-version VERSION` flag and
  versioned `entry_count` in `headers.json`. Different MH Frontier
  versions (Season 6, Forward.5, ZZ, etc.) have different numbers of
  items, armors, and weapons. Entry counts can be a plain integer
  (single version) or a version map (`{"zz": 14594, "ko": 1290}`).
  Defaults to ZZ.
- **Accent folding** via `--fold-unsupported-chars` for European-language
  imports. MH Frontier's bitmap font lacks Latin diacritics (é, è, à, ç,
  œ, etc.); this flag folds them to ASCII equivalents on import so they
  render in-game until the custom font is extended. Lossy and opt-in —
  source CSVs keep full typographic quality.
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
