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
1,Another string,Another translation
```

- `index` — slot number in the section's pointer table. Stable across
  upstream string-length changes that would shift raw offsets, so
  re-extractions and merges stay meaningful.
- `source` / `target` — original and translated text. A row is only
  imported if `target` differs from `source`.
- No `location` column; the source binary and xpath live in the JSON
  `metadata` block (`source_file`, `xpath`, `fingerprint`) or are
  inferred from the CSV filename (`dat-armors-head.csv` →
  `dat/armors/head`). `--xpath` only needs to be passed explicitly
  when the filename can't carry the mapping.

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
