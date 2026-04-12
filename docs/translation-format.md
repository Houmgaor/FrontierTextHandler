# Translation Format

This page documents the CSV/JSON format FrontierTextHandler produces
for translators, and the rules the importer uses when writing
translations back into the binary. Companion to
[`game-files.md`](game-files.md), which covers the source binaries
themselves.

## Two shapes on disk

Every extractor produces one of two shapes, selected at the CLI:

### Index-keyed (default since 1.6.0)

```csv
index,source,target
0,Original Japanese,New Translation
1,Another string,
```

- `index` — slot number in the section's pointer table. Stable across
  upstream string-length changes that would shift raw offsets, so
  re-extractions and merges stay meaningful.
- `source` — original text from the game binary. Treat as read-only.
- `target` — translator's output. Empty on fresh extract; fill it in
  to translate. Only non-empty rows where `target` differs from
  `source` are imported (see *`source` is a lock, not a document*
  below).
- No `location` column; the source binary and xpath live in the JSON
  `metadata` block (`source_file`, `version`, `format_version`,
  `xpath`, `fingerprint`) or are inferred from the CSV filename
  (`dat-armors-head.csv` → `dat/armors/head`). `--xpath` only needs
  to be passed explicitly when the filename can't carry the
  mapping. `version` is the tool version that produced the file;
  `format_version` is the shape version (currently `"1.6"`) so
  readers can detect on-disk changes without having to map tool
  versions.

### Legacy offset-keyed (opt-in via `--legacy-offset`)

```csv
location,source,target
0x64@mhfdat.bin,Original Japanese,New Translation
```

- `location` — pointer offset in hex `@filename`.
- Same semantics for `source` / `target`.
- Kept for interoperability with tooling that hasn't adopted the
  index-keyed format yet. The importer auto-detects which shape it's
  looking at, so both forms can coexist in a single project.

The `--with-index` flag from 1.5.0 is kept as a silent no-op alias
so pre-1.6.0 scripts keep working.

### Scope of the default

Every extraction entry point emits index-keyed output by default:
`--extract-all`, `--xpath=…`, `--quest`, `--scenario`, `--npc`,
`--ftxt`, and their batch counterparts (`--quest-dir`,
`--scenario-dir`, `--npc-dir`). The ReFrontier-compatible TSV path
(`export_for_refrontier`) and `refrontier_to_csv` stay offset-keyed
because ReFrontier inputs already carry raw pointer offsets and have
no section context to index against.

## Inline escapes

Two lexical transforms run at the CSV/JSON boundary. Both are
bijections — round-tripping an extracted CSV through the importer
reproduces the original byte sequence exactly.

### Color codes — `‾CNN` ↔ `{cNN}` / `{/c}`

The game encodes inline colour changes as the byte `0x7E` followed by
`C` and two decimal digits. In Shift-JIS X 0213 `0x7E` decodes as `‾`
(U+203E OVERLINE), frequently mangled by editors, diff tools, and
GitHub markdown. The brace form is ASCII-safe and matches the
existing `{K012}` / `{i131}` / `{u4}` keybind/icon placeholder
convention used throughout MHFrontier-Translation.

| On disk | In the binary | Meaning |
|---------|---------------|---------|
| `{cNN}` | `‾CNN`        | open a colour span |
| `{/c}`  | `‾C00`        | reset to default |

Unknown colour ids pass through with a warning rather than failing,
so newly-seen codes surface without breaking extraction.
`export_for_refrontier` is unchanged — the ReFrontier-compatible TSV
still carries raw game bytes.

### Grouped-entry join marker — `{j}`

Some sections (quest tables, NPC dialogue, multi-pointer entries)
pack several pointer slots into a single logical entry. The
extractors surface this as a single CSV/JSON row whose `source` /
`target` cells contain the sub-strings separated by `{j}`:

```
Hunter Basics{j}Deliver 2 Raw Meat{j}…
```

Translators edit the cell like any other, keeping the `{j}` markers
in place. The importer splits on `{j}` and aligns sub-strings
positionally against the live pointer table at import time, so every
sibling pointer moves with the translation — you never have to touch
or think about raw pointer addresses.

The marker is:

- **quote-free** — CSV writers don't wrap the cell in quotes and
  don't escape anything inside;
- **offset-free** — sub-pointer addresses are re-derived from a fresh
  re-extraction of the source binary at import time;
- **consistent** with `{cNN}` / `{/c}` so both transforms compose
  cleanly.

The importer accepts the legacy `<join at="N">` tag form as well,
for translation files written before 1.6.0 (see *Backward
compatibility* below).

### Placeholders to leave alone — `{K…}` / `{i…}` / `{u…}`

Some strings contain ASCII placeholders that the game substitutes at
runtime with the current keybind, an icon glyph, or an underlined
label. They come straight from the original game bytes — the tool
passes them through unchanged on both extract and import, and
translators should treat them as opaque markers:

| Placeholder | What the game substitutes |
|-------------|---------------------------|
| `{K012}`    | the key currently bound to action `012` |
| `{i131}`    | the inline icon glyph `131` |
| `{u4}`      | an underlined-label region of level 4 |

Rules of thumb for translators:

- **Never change the number.** `{K012}` means a specific action;
  renaming it to `{K013}` picks a different keybind at runtime.
- **Never translate or delete the placeholder itself.** Deleting a
  `{K012}` turns "Press {K012} to open the map" into "Press  to open
  the map" with a stray space and no runtime substitution. The
  placeholder validator (see below) catches this automatically.
- **Surrounding text is free game.** Reorder, translate, or rewrite
  the words around the placeholder however the target language
  demands.

The same "leave it alone" rule applies to `{cNN}` / `{/c}` and `{j}`.

### Placeholder validation

Every import runs a lightweight linter over the rows it reads
before they touch the binary. For each row whose `target` differs
from `source`, it compares the multiset of `{letter…}` /
`{/letter…}` markers across the two cells and flags anything that
doesn't match — a dropped `{cNN}`, a duplicated `{K012}`, a typo
like `{K013}` where `{K012}` was expected, or an invented placeholder
that never existed in the source.

By default the importers log a warning summary (first five rows with
details, `... and N more` for the rest) and keep going, so an
interactive run on a translation file with a handful of broken rows
still lands the good translations and surfaces the bad ones for
fixing. CI pipelines can opt into hard-fail mode:

```bash
python main.py --csv-to-bin fr/dat-weapons-melee-name.csv data/mhfdat.bin \
    --xpath=dat/weapons/melee/name --strict-placeholders \
    --compress --encrypt
```

With `--strict-placeholders` the first mismatch raises and no binary
is written, so the pipeline fails before a corrupt translation lands
in the output.

There's also a standalone command that lints a translation file
without touching any binary — useful as a pre-commit hook in a
translation repository:

```bash
python main.py --validate-placeholders fr/dat-weapons-melee-name.csv
```

Exits `0` when every row is clean, `1` with a per-row report when
at least one row has a mismatch:

```text
FAIL: 2 row(s) in fr/dat-weapons-melee-name.csv have placeholder mismatches:
  line 42: missing '{K012}' (source has 1, target has 0)
  line 117: missing '{/c}' (source has 1, target has 0)
  line 117: missing '{c05}' (source has 1, target has 0)
```

What the validator catches:

- **Dropped markers.** `{c05}Warning{/c}` → `Attention` drops both
  the colour span open and close.
- **Added markers.** Stray `{K013}` appearing in target with no
  counterpart in source.
- **Duplicated markers.** `{K012}{K012}` where source had exactly
  one.
- **Typos in the number.** `{K012}` → `{K013}` flags one missing
  and one extra.
- **Dropped `{j}` sub-strings.** Caught earlier and more clearly
  than the "sub-string count mismatch" error that would fire later
  in `resolve_indexes_against_entries`.

What it does **not** catch (by design):

- **Reordering.** `{c05}Level {i131}{/c}` → `Niveau {i131}
  {c05}atteint{/c}` is legitimate translator freedom.
- **Semantic validity of the number.** The validator doesn't know
  whether `{K999}` is a real keybind ID — only whether source and
  target agree on it. Unknown colour IDs are surfaced separately
  by `color_codes_to_csv` / `color_codes_from_csv` on the encode
  path.
- **Braces with spaces.** `{Not A Marker}` in natural text isn't
  matched by the regex, so it can't produce false positives on
  literal English-prose brace tokens.

Rows with an empty `target` (untranslated) are skipped by the
validator — they can't have a mismatch by construction.

Callers that need programmatic access can use
`src.validate_placeholders(source, target)` (pure function,
returns a list of `PlaceholderIssue`) or
`src.validate_translation_file(path, strict=False)` (reads a full
translation file, returns a populated `PlaceholderValidator`).

## Shift-JIS character set limitations

Translations eventually get encoded to Shift-JIS-2004 because that's
what the game reads. This imposes two separate constraints — one
about *encoding* (what Python can write), one about *rendering*
(what the game can draw).

### Encoding: the source of truth is Unicode

CSV and JSON files are UTF-8, so translators can use any Unicode
character they like in a `target` cell. On re-encode, any character
that has no Shift-JIS-2004 mapping fails with an `EncodingError` and
the tool names the offending row so you can fix it. The *source of
truth* stays in full Unicode — there's no lossy pre-normalisation
step at read time.

### Rendering: the in-game font is incomplete

The PC version of MHFrontier ships with custom bitmap fonts that
cover JIS X 0208 plus a small ASCII range. They do **not** cover
Latin glyphs with diacritics (`é è ê à â ô ù û î ç œ « »` …) nor
several common typographic punctuation marks. Writing those
characters as their proper Shift-JIS-2004 codepoints encodes
losslessly but renders as missing-glyph boxes or wrong glyphs
in-game.

### `--fold-unsupported-chars` (opt-in)

For European-language imports there's an opt-in flag on every
import command:

```bash
python main.py --csv-to-bin fr/dat-weapons-melee-name.csv data/mhfdat.bin \
    --fold-unsupported-chars --compress --encrypt
```

With this flag the importer runs a lossy character-folding pass just
before Shift-JIS encoding:

| Input | Folded |
|-------|--------|
| `é è ê ë` | `e e e e` |
| `à â`     | `a a`     |
| `ç`       | `c`       |
| `œ Œ`     | `oe Oe`   |
| `« »`     | `" "`     |
| `…`       | `...`     |
| `— –`     | `- -`     |

Full rules live in [`src/text_folding.py`](../src/text_folding.py).
The fold is intentionally restricted to the Latin-1 Supplement,
Latin Extended-A, and Latin Extended-B ranges — CJK text is
left untouched, so the same flag is safe on a binary that still
contains Japanese strings.

Translators should still author their CSVs with proper diacritics.
The fold happens *only* on the way to the binary, so the on-disk
translation file keeps full typographic quality and can be
re-emitted with diacritics once the custom font grows the missing
glyphs.

## Extractor entry shape

Every 1.6.0 extractor returns entries with this shape:

```python
{
    "offset": 0x162d60,                     # first sub-pointer slot
    "text": "Title{j}Objective{j}…",         # {j}-joined sub-strings
    "sub_offsets": [0x162d60, 0x162d64, …], # one slot per sub-string
}
```

- `offset` is the first sub-pointer slot address of the entry. For
  non-grouped entries (most sections) it's simply the single slot.
- `text` is the clean joined form translators see in CSV/JSON.
- `sub_offsets` lists every sub-pointer slot address — one per
  sub-string, in the same order. `rebuild_section` reads this field
  directly to know which pointer-table slots to rewrite, without
  having to parse offsets back out of the text.

For grouped entries with internal null siblings (e.g.
`[ptrA, 0, 0, ptrB]`) the skipped slots are absent from `sub_offsets`
and the text has one fewer `{j}` — so the layout stays consistent
between extract and re-extract, and positional alignment works
unchanged.

## How translations flow back into the binary

The importer is driven by four shared helpers, independent of which
extractor produced the file:

1. **Format detection** — `detect_translation_format` looks at the
   CSV header or JSON shape and returns `"index"` or `"offset"`.
2. **Reader** — `get_new_strings_indexed` (index-keyed) or
   `get_new_strings_auto` (legacy). Both run `color_codes_from_csv`
   on every target cell so `{cNN}` lands as `‾CNN` bytes.
3. **Resolver** —
   `resolve_indexes_against_entries` takes `(index, text)` pairs and
   a list of freshly-extracted live entries, and returns either:
   - a flat list of `(ptr_offset, sub_text)` pairs for the
     xpath-driven rebuild path, via `sub_offsets`; or
   - one `(entry_offset, "a{j}b{j}c")` pair per grouped entry for the
     standalone-format rebuilders, which split the joined text
     themselves.
4. **Writer** — `rebuild_section` (xpath-driven), `rebuild_ftxt`,
   `rebuild_npc_dialogue`, `rebuild_scenario_file`, or
   `apply_translations_from_release_json`. Each reads
   `entry["sub_offsets"]` directly when it needs to rewrite sibling
   pointer slots.

The resolver fails loudly when a grouped translation's sub-string
count doesn't match the live entry's — the file has drifted from the
binary and a re-extract + merge is required.

### `source` is a lock, not a document

The importer skips rows where `target` is empty or equals `source`.
That's a deliberate design choice — it lets a translation file carry
every row (translated and untranslated alike) without the importer
having to guess which ones are "real". Two consequences translators
should know about:

- **Do not edit `source`.** The fresh extractor writes `source` with
  the original text and leaves `target` empty. Your job is to fill
  in `target` and leave `source` alone.
- **Clearing `target` keeps the original.** If you clear a `target`
  cell (set it to empty) the row is treated as untranslated and the
  original game string is preserved.

If a merge-from-upstream genuinely changed the source text, the
`--merge` command handles it: it carries forward your `target` and
flags the row for manual review, instead of silently writing a stale
translation on top of a new source.

### Binary fingerprint check

Index-keyed JSON exports record a 16-char SHA-256 prefix of the
decrypted/decompressed source binary in `metadata.fingerprint`. At
import time the importer recomputes it on the target file and warns
loudly on mismatch — catching the case where a translation extracted
from one game version is being applied to a different version, or to
a binary that already has translations applied. CSV imports skip
this check (CSV stays metadata-free); use the JSON sidecar if you
want fingerprint protection.

### xpath inference

Index-keyed imports infer the section xpath from the JSON
`metadata.xpath` field, or from the CSV/JSON filename
(`dat-armors-head.csv` → `dat/armors/head`). `--xpath` only needs to
be passed explicitly to override the inference.

### Standalone file formats

FTXT, NPC dialogue, scenario, and standalone quest files all accept
both CSV/JSON shapes through `import_ftxt_from_csv`,
`import_npc_dialogue_from_csv`, `import_scenario_from_csv`, and
`import_from_csv`. Index-keyed files are resolved against a fresh
re-extraction of the source binary using positional alignment —
translators don't have to touch slot numbers or pointer offsets.

## Backward compatibility

FrontierTextHandler reads every pre-1.6.0 translation file without
any migration step:

- **Legacy `target == source` convention** — pre-1.6.0 files use
  `target == source` for untranslated rows instead of an empty
  `target`. The importer accepts both: it skips rows where `target`
  is empty *or* equals `source`.
- **Legacy offset-keyed CSV/JSON** — still readable; `--legacy-offset`
  exports the same shape for round-tripping.
- **Legacy `<join at="NNN">` tags** — `_JOIN_SPLIT_RE` matches both
  `{j}` and `<join at="-?\d+">` when splitting a grouped translation,
  and `parse_joined_text` still reads the embedded offsets out of
  legacy input text on the location-keyed path. Extractors never
  *produce* the tag form any more.
- **Brace-form colour codes in a legacy CSV** — no problem;
  `color_codes_from_csv` runs on every target regardless of the
  surrounding shape.

The deprecated `join_codes_to_csv` helper in `src/common.py` is kept
as a no-op alias so any caller that previously fed it extractor
output still works. It rewrites any residual `<join at="N">` tag in
its input and passes clean `{j}` text through unchanged.

## File format migration helper

Existing translation files that predate 1.6.0 can be migrated
lazily: reading them works as-is (see above), and running
`--xpath=<section>` to re-extract the same section produces a new
`{j}` / `{cNN}` file. The one-shot migration script that rewrote
146404 cells across 40 CSVs in
`MHFrontier-Translation/translations/{en,fr}/` at 1.6.0 time used
exactly this path.
