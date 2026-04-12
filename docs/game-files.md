# Game Files Reference

This page documents the Monster Hunter Frontier binary files that
FrontierTextHandler can extract text from, and what each xpath section
inside them holds. The authoritative pointer-table layout lives in
[`headers.json`](../headers.json) — this file is the human-readable companion.

All files are stored encrypted (ECD/EXF) and compressed (JKR) on disk.
The tool transparently decrypts and decompresses them on read, and can
re-compress and re-encrypt on write via `--compress --encrypt`.

## Quick file index

| File | Purpose | xpath prefix |
|------|---------|--------------|
| `mhfdat.bin` | Core game data: weapons, armors, items, monsters, ranks | `dat/` |
| `mhfpac.bin` | Hunter skills + generic UI/system text tables | `pac/` |
| `mhfinf.bin` | Quest definitions and per-quest text blocks | `inf/` |
| `mhfjmp.bin` | Jump / teleport menu | `jmp/` |
| `mhfgao.bin` | Felyne (cat) partner equipment, dialogue, skills | `gao/` |
| `mhfsqd.bin` | Squad / NPC partner names and squad-skill text | `sqd/` |
| `mhfrcc.bin` | Reception desk / event info text | `rcc/` |
| `mhfmsx.bin` | Mezeporta Festa item names and effects | `msx/` |
| `mhfnav.bin` | Hunter Navi (text fields not yet mapped) | `nav/` |

`--extract-all` auto-routes every xpath to the right file. With
`--xpath` the tool uses the prefix to pick the binary in `data/`.

## Extraction modes

Each section in `headers.json` uses one of these modes to locate its
pointer table:

| Mode | `headers.json` fields | Description |
|------|----------------------|-------------|
| **Flat pointer array** | `begin_pointer` + `entry_count` | Pointer to array start + number of entries. Each entry is a 4-byte pointer to a null-terminated Shift-JIS string. Supports `pointers_per_entry` for multi-pointer groups. |
| **Struct-strided** | `begin_pointer` + `entry_count` + `entry_size` + `field_offset` | String pointers embedded at a fixed byte offset within repeated structs. |
| **Null-terminated** | `begin_pointer` + `null_terminated` | Scans pointer groups until the first pointer of a group is zero. Supports `pointers_per_entry` for grouped arrays. |
| **Quest table** | `begin_pointer` + `quest_table` + `count_base_pointer` | Multi-level parser: walks a category table, follows quest struct pointers, reads text sub-pointers per quest. |
| **Scan region** | `begin_pointer` + `scan_region` + `scan_end_pointer` | Walks every 4-byte slot in a bounded region, emits only pointers landing on valid Shift-JIS boundaries. Used for mixed struct regions. |

`entry_count` accepts either a plain integer or a versioned map
(`{"zz": 14594, "ko": 1290}`) for multi-version support.

## Coverage summary

| File | Strings extracted | Status |
|------|------------------|--------|
| `mhfdat.bin` | ~17,000+ (weapons, armors, items, monsters, ranks, HH) | Complete |
| `mhfpac.bin` | ~3,600 (skills + ~3,365 UI/dialogue tables) | Complete |
| `mhfinf.bin` | ~22,700 (quests × 8 text fields each) | Complete |
| `mhfjmp.bin` | 53 (menu titles, descriptions, strings) | Complete |
| `mhfgao.bin` | 2,122 (Felyne equipment, dialogue, skills) | Complete |
| `mhfsqd.bin` | 190 (NPC names, squad skills, labels) | Complete |
| `mhfrcc.bin` | 28 (event titles + descriptions) | Complete |
| `mhfmsx.bin` | 34 (Festa item names + effects) | Complete |

All known translator-useful text in `client/pc/dat/*.bin` is extracted.

---

## `mhfdat.bin` — Core game data

The biggest data file. Holds most of what a player reads in menus.

### `dat/weapons/`
- `melee/name`, `melee/description` — Melee weapon names and descriptions.
- `ranged/name`, `ranged/description` — Ranged weapon names and descriptions
  (bowguns, bows). Description table uses a count-based pointer layout with
  4 pointers per entry.

### `dat/armors/`
Armor piece names per slot. Five sections:
`head`, `body`, `arms`, `waist`, `legs`. Each section is a contiguous
pointer table delimited by adjacent header pointers.

### `dat/items/`
- `name` — Item names.
- `description` — Item descriptions.
- `source` — Item source / acquisition text (where to get the item).

### `dat/monsters/`
- `description` — Monster description text shown in the hunter notes.

### `dat/equipment/`
- `description` — Equipment description blocks (grouped, 4 pointers per
  entry, null-terminated).

### `dat/ranks/`
HR rank requirement label/value pairs. The struct is 20 bytes per row
(2 string pointers + 12 bytes padding).
- `label` — e.g. "HR1+", "HR1~".
- `requirement` — Matching requirement description.

### `dat/hunting_horn/`
- `guide` — Hunting Horn note guide.
- `tutorial` — Hunting Horn tutorial text.

---

## `mhfpac.bin` — Skills and UI text

### `pac/skills/`
Hunter skill text, four parallel sections:
- `name` — Skill names.
- `effect` — Skill effect text (current generation).
- `effect_z` — Z-tier skill effect text.
- `description` — Skill descriptions.

### `pac/text_*`
Generic UI / system text tables. The numeric suffix is the header pointer
offset where the table base is stored. Two layout families coexist:

- **Null-terminated grouped tables** (`text_14`, `text_18`, `text_1c`,
  `text_20`, `text_24`, `text_28`, `text_2c`, `text_30`, `text_34`,
  `text_50`, `text_54`): flat `s32p` arrays terminated by a 0 pointer.
  `pointers_per_entry` defines how many strings make up one logical row
  (ranges from 2 up to 92 for `text_30`).

- **Count-based strided tables** (`text_40`, `text_44`, `text_60`,
  `text_64`, `text_68`, `text_6c`, `text_94`, `text_c8`, `text_cc`,
  `text_d0`, `text_d4`): fixed-stride structs with the row count stored
  at a known header offset. Some tables (`text_94`) carry two string
  pointers per row, exposed as `field_0` / `field_1`.

- **Fixed-count struct table** (`text_48`): 423 entries × 8 bytes
  (skill tree / decoration name pairs), exposed as `field_0` / `field_1`.

These tables hold things like menu strings, prompts, status messages and
internal labels. Mapping each individual `text_*` to a player-visible
feature is ongoing reverse-engineering work; treat them as "generic UI
strings" for now.

---

## `mhfinf.bin` — Quest data

### `inf/quests`
Multi-level quest table. Each quest carries 8 text strings, exported
as a single `{j}`-joined row per quest. The fields in order:

| # | Label | In-game location |
|:-:|-------|------------------|
| 1 | title | Quest name in the list |
| 2 | textMain | Main objective text |
| 3 | textSubA | Sub-objective A |
| 4 | textSubB | Sub-objective B |
| 5 | successCond | Clear / success condition |
| 6 | failCond | Failure condition |
| 7 | contractor | Quest client name |
| 8 | description | Client request / flavour text |

Driven by `quest_table: true` mode in the extractor.

---

## `mhfjmp.bin` — Jump / teleport menu

Small file with 24 menu entries.

### `jmp/menu/`
- `title` — Entry titles (field offset 48 in a 56-byte struct).
- `description` — Entry descriptions (field offset 52).

### `jmp/strings`
Auxiliary string table referenced from header pointer 0x0C with the
count stored at 0x10.

---

## `mhfgao.bin` — Felyne partner data

Felyne (cat) companion equipment, dialogue templates and skill text.
2,122 strings across 16 sections.

### Equipment
- `armor_helm` — Felyne head armor names (ネコヘルム). Fixed at 257
  entries because a `YYYY/MM/DD` build-date ASCII string is stored
  between the table end and its 0 terminator, which would otherwise
  break null-terminated detection.
- `armor_mail` — Felyne body armor names (ネコメイル).
- `weapon_names` — Felyne weapon names. 257 entries; the first three
  are English fallbacks (`None`, `Cat Bone Pick`, `Cat Paw Punch`)
  pointing into the English text region at `0x34000+`.
- `armor_desc` — Felyne armor descriptions. Flat `s32p` array, 3
  strings per description followed by a 0 terminator (4 ptrs per group).
- `weapon_desc` — Felyne weapon descriptions. Same layout as
  `armor_desc`.

### Dialogue
- `dialogue_type_0` … `dialogue_type_7` — 8 personality-type dialogue
  templates, ~40 lines each:

  | Type | Personality |
  |:---:|---|
  | 0 | Enthusiastic / cat-fighter |
  | 1 | Humble / grateful |
  | 2 | Timid / anxious |
  | 3 | Aloof / self-reliant |
  | 4 | Earnest / trainee |
  | 5 | Polite / respectful |
  | 6 | Cheerful / spirited |
  | 7 | Cool / casual |

- `situational_dialogue` — Situational Felyne lines extracted from a
  mixed struct region at `0x21fe0..0x22880`. The region interleaves
  string pointers, mid-character substring references (the runtime
  composition engine), numeric IDs / bitfields, and padding. Walked via
  `scan_region` mode which only emits pointers landing on a clean
  Shift-JIS character boundary. Substring references stay in the file
  and continue to resolve to the original Japanese bytes at runtime
  (worst case: a partial Japanese fragment alongside a translated full
  line).

### Skills
- `skill_text` — 238 entries: `[0..1]` are English headers, `[2..55]`
  are 54 Japanese skill effect descriptions, `[56..237]` are 182 English
  skill name/description strings.
- `skill_names_zenith` — 9 English Zenith / Myriad Felyne skill names
  (Status Immunity, Status Immunity Myriad, No Stamina Depletion S/L,
  Elemental Attack Up, Affinity Up S/L, Divine Protection, Goddess'
  Embrace).

---

## `mhfsqd.bin` — Squad / NPC partner data

~190 strings across 6 sections. The file header at `0x00..0x38` stores
15 `u32` pointers that delimit struct-strided tables; string pointers
are embedded as fields within structs (not flat `s32p` arrays).

- `npc_names` — NPC partner names (Aaron, Bart, Calvin, Tania, ...).
  43 entries, stride 8.
- `star_rank` — Star rank labels (one/two/three stars). 3 entries.
- `skill_activation` — "Skill X activates." messages. 35 entries,
  stride 16, string at field +8.
- `skill_description` — Squad skill descriptions. 26 entries, stride
  12, string at field +4.
- `skill_quest_label` — Skill quest-count labels ("Usable 5 times per
  quest", ...). 80 entries.
- `header_labels` — Header / placeholder labels (point suppression,
  point reset). 3 entries; layout is irregular and only field +4 is
  reliably a string across all rows.

Tables at header offsets `0x00/0x04/0x08/0x0C/0x1C/0x20/0x2C/0x30/0x34/0x38`
are non-string or complex and not yet extracted.

---

## `mhfrcc.bin` — Reception / event info

Reception desk text. 28 strings across 2 sections.

- `events_en` — English event info, 7 entries via a contiguous `s32p`
  table pointed to by the `u32` at `0x08`.
- `events_full` — Multi-field struct table at `0x5c0` (7 rows × 36-byte
  stride). Each row carries up to 4 string pointer fields at offsets
  `+0x14` (title), `+0x18` (description / alt title), `+0x1C` and
  `+0x20` (usually `−` placeholders, but row 1 stores
  `Guild Conquest is underway!` and a `残り時間…` template).
  Supersets `events_en`.

---

## `mhfmsx.bin` — Mezeporta Festa

17 item names + 17 item effects. A 17-entry struct-strided table at the
literal file offset `0x2abc` (no header pointer dereference) containing
`(name_ptr, desc_ptr)` pairs per `0x24`-byte struct. Most slots are
`----` placeholders; ~10 slots contain real item names and their
effect descriptions.

- `item_name` — Name pointer at field `+0x00`.
- `item_effect` — Effect pointer at field `+0x04`.

---

## `mhfnav.bin` — Hunter Navi

Hunter Navi data. Contains task reward tables (item ID + quantity),
character index lists, and numerical metadata. ImHex patterns confirm
no `s32p` string fields. Binary scan of the decrypted file found zero
readable strings.

---

## Files without extractable text

These `client/pc/dat/` files were checked and contain no translatable
text:

| File | Content |
|------|---------|
| `mhfemd.bin` | Monster stat tables (numeric only) |
| `mhfmec.bin` | 960 bytes, numeric/float data |
| `mhfmfd.bin` | Coordinate/float data |
| `mhfsch.bin` | Schedule data (dates) |
| `mhfsdt.bin` | Sound/animation data |
| `rengoku_data.bin` | Hunter's Road spawn tables (numeric) |
| `guildcard.bin` | Empty file (0 bytes) |
| `effect.bin`, `mhf.bin`, `mhf_90c.bin` | Archives or binary blobs |
| `micon*.bin`, `mytra.bin`, `result.bin` | Image data |
| `wallpaper_*.bin` | Image archives (MOMO/MHA) |
| `*.txb` | PNG image containers (some ECD-wrapped) |

---

## See also

- [`headers.json`](../headers.json) — exact pointer offsets and
  extraction modes for every section above.
- [`README.md`](../README.md) — extraction commands, CSV/JSON formats,
  and the import workflow.
