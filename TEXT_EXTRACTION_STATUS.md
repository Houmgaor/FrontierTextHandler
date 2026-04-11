# Text Extraction Status

Tracks what text FrontierTextHandler can extract, what remains to be done, and the technical details needed to implement each section.

Last updated: 2026-02-22

## How extraction works

FrontierTextHandler reads text from Monster Hunter Frontier game files using these extraction modes, configured in `headers.json`:

| Mode | headers.json fields | Description |
|------|-------------------|-------------|
| **Pointer-pair** | `begin_pointer` + `next_field_pointer` | Two pointers in the file header define the start and end of a contiguous `s32p` array. Each `s32p` is a 4-byte pointer to a null-terminated Shift-JIS string. |
| **Count-based** | `begin_pointer` + `count_pointer` | A pointer to the array start + a count field. Array length = count * 4. |
| **Struct-strided** | `begin_pointer` + `entry_count` + `entry_size` + `field_offset` | String pointers embedded at a fixed byte offset within repeated structs. |
| **Indirect count (flat)** | `begin_pointer` + `count_base_pointer` + `count_offset` | Count stored as u16/u32 at an address computed by dereferencing a base pointer + offset. Supports `pointers_per_entry` for grouped pointer arrays (e.g., s32px4) and `count_adjust` for ±1 corrections. |
| **Indirect count (strided)** | `begin_pointer` + `count_base_pointer` + `entry_size` + `field_offset` | Same indirect count mechanism, but reads from struct-strided arrays instead of flat pointer tables. |
| **Null-terminated** | `begin_pointer` + `null_terminated` | Scans pointer groups until the first pointer of a group is zero. Supports `pointers_per_entry` for grouped pointer arrays. |
| **Quest table** | `begin_pointer` + `quest_table` + `count_base_pointer` | Multi-level parser: walks a category table, follows quest struct pointers, reads text sub-pointers per quest. All 8 strings per quest are joined with `<join>` tags. |

All files are auto-decrypted (ECD/EXF) and auto-decompressed (JPK/JKR) before parsing.

---

## mhfdat.bin — Main game data

Source: `client/pc/dat/mhfdat.bin` (ECD-encrypted)
Header documentation: `docs/mhfdat.md`, `patterns/mhf-patterns/mhfdat/header.hexpat`
Decompile pattern: `patterns/mhf-patterns/mhfdat/decompile.hexpat`

### Extracted

| xpath | Pointer | Content | Mode |
|-------|---------|---------|------|
| `dat/armors/head` | 0x064 | Head armor names | pointer-pair (end: 0x060) |
| `dat/armors/body` | 0x068 | Body armor names | pointer-pair (end: 0x064) |
| `dat/armors/arms` | 0x06C | Arm armor names | pointer-pair (end: 0x068) |
| `dat/armors/waist` | 0x070 | Waist armor names | pointer-pair (end: 0x06C) |
| `dat/armors/legs` | 0x074 | Leg armor names | pointer-pair (end: 0x070) |
| `dat/weapons/melee/name` | 0x088 | Melee weapon names | pointer-pair (end: 0x174) |
| `dat/weapons/melee/description` | 0x08C | Melee weapon descriptions | pointer-pair (end: 0x040) |
| `dat/weapons/ranged/name` | 0x084 | Ranged weapon names | pointer-pair (end: 0x088) |
| `dat/weapons/ranged/description` | 0x090 | Ranged weapon descriptions | indirect-count (base: 0x0E8, +0x0E, s32px4) |
| `dat/items/name` | 0x100 | Item names | pointer-pair (end: 0x0FC) |
| `dat/items/description` | 0x12C | Item descriptions | pointer-pair (end: 0x100) |
| `dat/items/source` | 0xA40 | Item source/acquisition text | indirect-count (base: 0x010, +0x08) |
| `dat/monsters/description` | 0x134 | Monster descriptions | indirect-count (base: 0x010, +0x22) |
| `dat/equipment/description` | 0x078 | Equipment descriptions (all armor + weapons) | null-terminated (s32px4) |
| `dat/ranks/label` | 0x168 | Rank requirement labels ("HR1+") | indirect-count strided (base: 0x010, +0x4E, +1, size: 20, field: 0) |
| `dat/ranks/requirement` | 0x168 | Rank requirement ranges ("HR1~") | indirect-count strided (base: 0x010, +0x4E, +1, size: 20, field: 4) |
| `dat/hunting_horn/guide` | 0x180 | Hunting Horn guide pages | indirect-count (base: 0x010, +0x26) |
| `dat/hunting_horn/tutorial` | 0x184 | Hunting Horn tutorial pages | indirect-count (base: 0x010, +0x28) |

### Not yet extracted

All documented text fields in mhfdat.bin are now extracted.

Note on `important_nums`: Several counts are stored as `u16` values at offsets within the data block pointed to by header offset 0x010. The exact offset depends on game version (Wii U: `+0x272` range, PC G10-ZZ: `+0x350` range). The indirect-count extraction mode reads these automatically.

---

## mhfpac.bin — Skill and UI data

Source: `client/pc/dat/mhfpac.bin` (ECD-encrypted)
Decompile pattern: `patterns/mhf-patterns/mhfpac/decompile.hexpat`

### Extracted

| xpath | Pointer | Content | Mode |
|-------|---------|---------|------|
| `pac/skills/name` | 0xA20 | Skill point names | pointer-pair (end: 0xA1C) |
| `pac/skills/effect` | 0xA1C | Activated skill names | pointer-pair (end: 0xBC0) |
| `pac/skills/effect_z` | 0xFBC | Zenith skill names | pointer-pair (end: 0xFB0) |
| `pac/skills/description` | 0x0B8 | Skill descriptions | pointer-pair (end: 0x0C0) |
| `pac/text_14` | 0x14 | UI labels group A ("Status", …) — 4×3 = 12 strings | null-terminated grouped (pointers_per_entry: 3) |
| `pac/text_18` | 0x18 | UI labels group B ("Discard", …) — 6×4 = 24 strings | null-terminated grouped (pointers_per_entry: 4) |
| `pac/text_1c` | 0x1C | UI labels group C — 12×5 = 60 strings | null-terminated grouped (pointers_per_entry: 5) |
| `pac/text_20` | 0x20 | UI labels group D — 3×3 = 9 strings | null-terminated grouped (pointers_per_entry: 3) |
| `pac/text_24` | 0x24 | Quest/status screen labels ("Quest Name:", …) — 25×19 = 475 strings | null-terminated grouped (pointers_per_entry: 19) |
| `pac/text_28` | 0x28 | Menu labels A ("Item", …) — 2×8 = 16 strings | null-terminated grouped (pointers_per_entry: 8) |
| `pac/text_2c` | 0x2C | Menu labels B — 5×10 = 50 strings | null-terminated grouped (pointers_per_entry: 10) |
| `pac/text_30` | 0x30 | Settings/options labels ("Hide HUD", …) — 2×92 = 184 strings | null-terminated grouped (pointers_per_entry: 92) |
| `pac/text_34` | 0x34 | Toggle labels ("ON", …) — 92×4 = 368 strings | null-terminated grouped (pointers_per_entry: 4) |
| `pac/text_40` | 0x40 | Loading screen text — 607 strings | indirect-count strided (nums+0x04, size 8, field 4) |
| `pac/text_44` | 0x44 | Felyne Elder dialogue — 106 strings | indirect-count strided (nums+0x06, size 8, field 4) |
| `pac/text_48/field_0` | 0x48 | Skill tree / decoration names (first of pair) — 423 strings | struct-strided (fixed 423, size 8, field 0) |
| `pac/text_48/field_1` | 0x48 | Skill tree / decoration names (second of pair) — 423 strings | struct-strided (fixed 423, size 8, field 4) |
| `pac/text_50` | 0x50 | Additional skill names A — 50×2 = 100 strings | null-terminated grouped (pointers_per_entry: 2) |
| `pac/text_54` | 0x54 | Additional skill names B — 50×2 = 100 strings | null-terminated grouped (pointers_per_entry: 2) |
| `pac/text_60` | 0x60 | Controller labels: Frontier Type — 7 strings | indirect-count strided (nums+0x22, size 16, field 0) |
| `pac/text_64` | 0x64 | Controller labels: Attack Type — 4 strings | indirect-count strided (nums+0x24, size 16, field 0) |
| `pac/text_68` | 0x68 | Controller labels: Classic Type — 3 strings | indirect-count strided (nums+0x26, size 16, field 0) |
| `pac/text_6c` | 0x6C | Controller labels: Common Actions — 18 strings | indirect-count strided (nums+0x28, size 16, field 0) |
| `pac/text_94/field_0` | 0x94 | Character customization label — 153 strings | indirect-count strided (nums+0x1C, size 16, field 4) |
| `pac/text_94/field_1` | 0x94 | Character customization detail — 153 strings | indirect-count strided (nums+0x1C, size 16, field 8) |
| `pac/text_c8` | 0xC8 | Partner dialogue A (Felyne shop) — 22 strings | indirect-count strided (nums+0x52, size 12, field 0) |
| `pac/text_cc` | 0xCC | Partner dialogue B (quest departure) — 11 strings | indirect-count strided (nums+0x54, size 12, field 0) |
| `pac/text_d0` | 0xD0 | Partner dialogue C (NPC speech) — 13 strings | indirect-count strided (nums+0x5A, size 12, field 0) |
| `pac/text_d4` | 0xD4 | Partner dialogue D (Felyne speech) — 24 strings | indirect-count strided (nums+0x5C, size 12, field 0) |

All documented text fields in mhfpac.bin are now extracted. Grouped sections (`text_14`..`text_54`) emit multi-string CSV rows separated by `{j}` markers (1.6.0+; pre-1.6.0 CSVs used `<join at="N">` tags, still accepted by the importer for backward compatibility) and require `--xpath=pac/text_XX` on `csv-to-bin` so `rebuild_section` is used.

### Verified string counts (from `data/mhfpac.bin`, decrypted size 2,259,385 B)

Total newly surfaced strings: **~3,365** across 25 xpaths (previously only 4 skill sections were extracted).

---

## mhfjmp.bin — Jump/teleport menu

Source: `client/pc/dat/mhfjmp.bin` (ECD-encrypted)
Pattern: `patterns/mhf-patterns/mhfjmp.bin.hexpat`

### Extracted

| xpath | Pointer | Content | Mode |
|-------|---------|---------|------|
| `jmp/menu/title` | 0x00 | Menu entry titles (24 entries) | struct-strided (size: 56, offset: 48) |
| `jmp/menu/description` | 0x00 | Menu entry descriptions (24 entries) | struct-strided (size: 56, offset: 52) |
| `jmp/strings` | 0x0C | UI strings (count at 0x10) | count-based |

All text in this file is fully extracted.

---

## mhfinf.bin — Quest information

Source: `client/pc/dat/mhfinf.bin` (ECD-encrypted)
Documentation: `docs/mhfinf.md`
Pattern: `patterns/mhf-patterns/mhfinf.bin.hexpat`

### Extracted

| xpath | Pointer | Content | Mode |
|-------|---------|---------|------|
| `inf/quests` | 0x14 | Quest text (~2,800 quests × 8 strings: title, objectives, conditions, contractor, description) | quest-table (category count at 0x10+0x00, text at quest+0x28) |

The 8 strings per quest are joined with `<join>` tags in a single CSV row:

| Sub-offset | Content |
|------------|---------|
| +0x00 | Quest title |
| +0x04 | Main objective text |
| +0x08 | Sub A objective text |
| +0x0C | Sub B objective text |
| +0x10 | Success conditions |
| +0x14 | Fail conditions |
| +0x18 | Contractor (quest giver) name |
| +0x1C | Quest description / flavor text |

All text in this file is fully extracted.

---

## mhfnav.bin — Hunter Navi

Source: `client/pc/dat/mhfnav.bin` (ECD-encrypted)
Pattern: `patterns/mhf-patterns/mhfnav.bin.hexpat`

**No text found.** The file contains task reward tables (item ID + quantity), character index lists, and numerical metadata. Both ImHex pattern versions confirm no `s32p` fields. Binary scan of the decrypted file found zero readable strings.

---

## Other game files

## mhfgao.bin — Felyne partner / companion data

Source: `client/pc/dat/mhfgao.bin` (ECD-encrypted + JKR-compressed; decrypted size 218,981 B)
Pattern: none. Header layout reverse-engineered by scanning header pointers for pointer tables that target the main Shift-JIS string region at 0x0001A0–0x00C62F (~1,559 unique strings).

### Extracted

| xpath | Pointer | Content | Mode |
|-------|---------|---------|------|
| `gao/armor_helm` | 0x18 | Felyne head armor names (ネコヘルム) — 257 entries | struct-strided (fixed 257, size 4, field 0) |
| `gao/armor_mail` | 0x1C | Felyne body armor names (ネコメイル) — 257 entries | null-terminated |
| `gao/weapon_names` | 0x28 | Felyne weapon names — 257 entries (first 3 are English fallbacks) | struct-strided (fixed 257, size 4, field 0) |
| `gao/armor_desc` | 0x20 | Felyne armor descriptions — 514 entries, 3 lines/entry joined with `<join>` | null-terminated grouped (pointers_per_entry: 4) |
| `gao/weapon_desc` | 0x2C | Felyne weapon descriptions — 257 entries, 3 lines/entry joined with `<join>` | null-terminated grouped (pointers_per_entry: 4) |
| `gao/dialogue_type_0` | 0x90 | Felyne partner dialogue template, personality 0 — 40 lines | null-terminated |
| `gao/dialogue_type_1` | 0x94 | Felyne partner dialogue template, personality 1 — 40 lines | null-terminated |
| `gao/dialogue_type_2` | 0x98 | Felyne partner dialogue template, personality 2 — 40 lines | null-terminated |
| `gao/dialogue_type_3` | 0x9C | Felyne partner dialogue template, personality 3 — 40 lines | null-terminated |
| `gao/dialogue_type_4` | 0xA0 | Felyne partner dialogue template, personality 4 — 40 lines | null-terminated |
| `gao/dialogue_type_5` | 0xA4 | Felyne partner dialogue template, personality 5 — 40 lines | null-terminated |
| `gao/dialogue_type_6` | 0xA8 | Felyne partner dialogue template, personality 6 — 40 lines | null-terminated |
| `gao/dialogue_type_7` | 0xAC | Felyne partner dialogue template, personality 7 — 40 lines | null-terminated |
| `gao/skill_text` | 0x124 | Felyne skill descriptions + English skill names — 238 entries: [0..1] EN headers ("None", "Disables wind pressure."), [2..55] 54 JP skill effect descriptions (previously the "orphan 0x13EC8" region — reachable here as entries [2..55]), [56..237] 182 EN skill names | struct-strided (fixed 238, size 4, field 0) |
| `gao/skill_names_zenith` | 0x12C | English Zenith/Myriad Felyne skill names — 9 entries (Status Immunity, No Stamin Depletion, Elemental Attack Up, Affinity Up, Divine Protection, Goddess' Embrace, …) | struct-strided (fixed 9, size 4, field 0) |
| `gao/situational_dialogue` | 0x40 | Situational Felyne dialogue region `0x21fe0..0x22880` — 13 unique full dialogues (monster-sighting, quest-finish, Gania cat-head, end-of-day monologue, Rurufuru helm flavor, horn-buff effect, …) — extracted via scan_region mode after filtering mid-character composition-engine fragments | scan_region (pointer-pair bounds, min_length 4) |

**2,122 strings** extracted across 16 header-rooted tables: 2×257 armor names, 257 weapon names, 514 armor descriptions, 257 weapon descriptions, 8×40 Felyne partner dialogue templates, 238 Felyne skill description / English name entries at 0x124, 9 Zenith Felyne skill names at 0x12C, and 13 situational dialogue entries at 0x40.

Layout notes:
- `armor_helm` and `weapon_names` use fixed entry_count because an ASCII build-date string ("YYYY/MM/DD") is stored between the table end and its 0 terminator, which breaks null-terminated scanning.
- `armor_desc` and `weapon_desc` use a flat s32p array where each description is 3 string pointers followed by a 0 terminator (4 ptrs per group). Row 0 of each table is an English fallback ("Nothing equipped." / "None") pointing into a second English text region at `0x34000`-`0x35765`.
- Two distinct text regions exist: Japanese at `0x0001A0`-`0x00C62F` (~1,559 unique strings) and English at `0x034000`-`0x035765`.

### Not yet extracted

| Pointer | Evidence | Est. strings | Notes |
|---------|----------|-------------|-------|
| 0x040 | header → 0x21FE0, situational dialogue region | — | **Resolved via scan_region mode (2026-04-06).** The 552 u32 slots in the region split into 154 null / 188 OOB (numeric IDs, not pointers) / 55 clean-start pointers (18 unique) / 143 mid-character fragment pointers (37 unique). Fragments are runtime composition-engine references whose byte offsets depend on the exact Shift-JIS layout of the original text and would break under translation. The new `scan_region` extraction mode walks every 4-byte aligned slot in `[begin, end)`, rejects OOB values and pointers whose target is preceded by a Shift-JIS lead byte, and emits the 13 translator-usable full dialogues (after min_length=4 to drop 2–3 byte numeric coincidences). Fragment pointers remain in the file and continue to resolve to the original Japanese bytes at runtime; worst-case visual effect is a partial replay in JP while the full line is shown in the translation. |
| nested 0xCC/0xD4/0xDC | `count=8` at 0x0C8/0x0D0/0x0D8, then 3-level `(count, ptr)` trees at 0x19380 / 0x15F80 / 0x15140 | ~16 unique fragments (not ~250) | Tree walk confirmed: outer array of 8 × (u32 count, u32 ptr) → middle array of *count* × (u32 count, u32 ptr) → leaf array of *count* × s32p. Walking all three trees yields only ~16 unique readable strings, and the rest of the leaf pointers land mid Shift-JIS character (same compositional tokenization as 0x040). Interpretation: these are the per-skill **effect formula tables** that the game uses to build the skill description shown in `gao/skill_text` at runtime — each leaf entry glues a fragment like `耐性値が上昇する。` to a numeric prefix to produce "X resistance rises." etc. The translator-usable strings are already captured via `gao/skill_text`; these tables carry no additional unique translatable content. Implementing a recursive walker is feasible but not worthwhile for translation output. |
| orphan 0x13EC8 | 54 Felyne JP skill effect descriptions | — | **Resolved.** Not actually orphan: header pointer `0x124 → 0x13EC0` references a 238-entry s32p table that contains these 54 JP descriptions as entries [2..55]. Now fully extracted via `gao/skill_text`. |

Remaining unextracted text in mhfgao.bin: **~0**. The 0x040 situational dialogue is now covered by `gao/situational_dialogue` (13 entries), and the 0xCC/0xD4/0xDC nested trees carry no additional translatable strings beyond fragment tokens already represented by `gao/skill_text`.

---

## Other game files

## mhfsqd.bin — Squad / NPC partner data

Source: `client/pc/dat/mhfsqd.bin` (ECD-encrypted + JKR-compressed; decrypted+decompressed size 16,036 B)
Pattern: none. Greenfield reverse-engineered by scanning the 15 u32 pointers at 0x00-0x38 for struct-strided tables whose embedded string pointer fields target the flat Shift-JIS blob at 0x40-0x14C0 (223 null-terminated strings).

### Extracted

| xpath | Pointer | Content | Mode |
|-------|---------|---------|------|
| `sqd/npc_names` | 0x28 | NPC partner names (Aaron, Bart, Calvin, Tania, ...) — 43 entries | struct-strided (size 8, field 0) |
| `sqd/star_rank` | 0x24 | Star rank labels (★, ★★, ★★★) — 3 entries | struct-strided (size 8, field 0) |
| `sqd/skill_activation` | 0x18 | Squad skill activation messages — 35 entries | struct-strided (size 16, field 8) |
| `sqd/skill_description` | 0x14 | Squad skill descriptions — 26 entries | struct-strided (size 12, field 4) |
| `sqd/skill_quest_label` | 0x10 | Skill quest-count labels ("Usable N times per quest") — 80 entries | struct-strided (size 12, field 4) |
| `sqd/header_labels` | 0x38 | Header / placeholder labels (point suppression, point reset) — 3 entries | struct-strided (size 12, field 4) |

**190 strings** extracted across 6 header-rooted struct-strided tables. All tables are bounded exactly by the next header pointer (each header slot at 0x00-0x38 delimits one struct section).

### Not yet extracted

Investigation (2026-04-06) revised the remaining-string estimate sharply downward. Inspecting the two candidate tables at runtime:
- Header 0x38 -> 0x14E0 (0x30 B, 12 u32): 12-byte stride `(index, name_ptr, template_ptr)` with only 3 populated rows. Already fully extracted by `sqd/header_labels` — the remaining cells are 1 shared effect template (`効果\n…`) plus null padding. **0 new strings.**
- Header 0x34 -> 0x1510 (16 B): flag words only, no strings.
- Header 0x30 -> 0x1520 (0x120 B, 72 u32): pointer-to-pointer network whose leaf values are of the form `0x0001019c` — **skill IDs, not file offsets** (they exceed the 0x3EA4 file size). Cross-references to the skill table already extracted elsewhere. Entries that do point into 0x27A0-0x27B4 land on an all-null region in this file version. **0 new strings.**
- Headers 0x00/0x04/0x08/0x0C/0x1C/0x20/0x2C point to non-string data (floats, indices, tables of struct IDs).

Net remaining translator-useful strings in sqd: **~0**. The earlier ~33 estimate was wrong — it counted ID cross-references and layout padding as strings.

## mhfrcc.bin — Reception / event info

Source: `client/pc/dat/mhfrcc.bin` (ECD-encrypted + JKR-compressed; decrypted+decompressed size 2,556 B).
Pattern: none. Greenfield reverse-engineered by scanning decrypted bytes for Shift-JIS runs and cross-referencing u32 values to candidate string pointers.

### Extracted

| xpath | Pointer | Content | Mode |
|-------|---------|---------|------|
| `rcc/events_en` | 0x08 | English event-info strings (Pallone Grand Voyage, Hunter Fest, Hunting Competition, ...) — 7 entries | struct-strided (fixed 7, size 4, field 0) |
| `rcc/events_full` | 0x00 | Event info multi-field struct table at 0x5c0: 7 rows × 36-byte stride with up to 4 string ptr fields per row (+0x14 title / +0x18 description / +0x1C / +0x20). Captures JP descriptions (パローネ大航祭, 極限征伐戦, 天廊遠征録), `Guild Conquest is underway!`, and the `残り時間` template — 28 entries | struct-strided (multi-field [20,24,28,32]) |

Re-investigation on 2026-04-06 confirmed the region is a uniform 36-byte stride (not variable), bounded exactly by header 0x00=0x5c0 and header 0x04=7. Handled by upgrading `struct-strided` to support multi-field `field_offset` (int or list[int]) in `pointer_tables.py`.

### Not yet extracted

No remaining translator-useful strings in the 0x5c0-0x6c0 region — the earlier ~27-string estimate was wrong. Several slots in `events_full` are `−` placeholders (rows that define only title+description), which is expected game data, not missing coverage.

## mhfmsx.bin — Mezeporta Festa

Source: `client/pc/dat/mhfmsx.bin` (ECD-encrypted + JKR-compressed; decrypted+decompressed size 15,072 B).
Pattern: none. Greenfield reverse-engineered by locating the only readable Shift-JIS block (0x80-0xf8) and walking the nearest backing struct table.

### Extracted

| xpath | Base | Content | Mode |
|-------|------|---------|------|
| `msx/item_name` | 0x2abc (literal) | Festa item names: 輝く杯, 宝飾剣, 古書物, 小箱, 燭台 + 12 `----` placeholder slots — 17 entries | struct-strided literal_base (size 0x24, field 0) |
| `msx/item_effect` | 0x2abc (literal) | Festa item effects: 踏破報酬枠追加, 踏破報酬抽選確率アップ, TRP増加, 狩人祭効果発動, パローネ大航祭効果発動 + placeholders — 17 entries | struct-strided literal_base (size 0x24, field 4) |

10 real Japanese strings (5 names + 5 effects) recovered out of 34 struct slots in this section. A new `literal_base: true` flag on the struct-strided extraction mode was added to `pointer_tables.py` so that the struct base address (0x2abc) can be specified directly when no header u32 happens to hold it.

### Not yet extracted

Any additional localized strings referenced from sibling struct tables elsewhere in mhfmsx.bin. Color labels (赤, 青, 黄) at ~0x2d30 sit in a different layout and are not currently exposed.

### Without text

| File | Reason |
|------|--------|
| `mhfemd.bin` | Monster stat tables. ImHex pattern (`mhfemd.bin.hexpat`) confirms no string fields. |
| `mhfmec.bin` | 960 bytes. Numeric/float data only. |
| `mhfmfd.bin` | Coordinate/float data. No text. |
| `mhfsch.bin` | Schedule data (dates). No text. |
| `mhfsdt.bin` | Sound/animation data. No text. |
| `rengoku_data.bin` | Hunter's Road spawn tables. Pattern confirms numeric only. |
| `effect.bin`, `mhf.bin`, `mhf_90c.bin`, `micon*.bin`, `mytra.bin`, `result.bin`, `wallpaper_*.bin` | Archives (MOMO/MHA), images, or LZMA packages. Not directly parseable as text files. |
| `guildcard.bin` | Empty file (0 bytes). |

---

## Summary

| Category | Strings extracted | Strings remaining | Blocking issue |
|----------|------------------|-------------------|----------------|
| mhfdat.bin — names | ~thousands | 0 | - |
| mhfdat.bin — descriptions | all (melee, ranged, equipment, monster, item source) | 0 | - |
| mhfdat.bin — misc | rank labels, HH guides/tutorials | 0 | - |
| mhfpac.bin — skills | ~hundreds | 0 | - |
| mhfpac.bin — UI/dialogue | ~3,365 | 0 | - |
| mhfjmp.bin | 53 | 0 | - |
| mhfinf.bin — quests | **~22,700** | 0 | - |
| mhfgao.bin — Felyne | 2,122 (armor/weapon names+descs, dialogue, skill descriptions/names, situational dialogue via scan_region) | 0 | - |
| mhfsqd.bin — Squad | 190 (NPC names, skills, labels) | ~0 (earlier ~33 estimate was IDs/padding, not strings) | None actionable |
| mhfrcc.bin — Reception | 28 (7 EN titles + 7 JP/EN descriptions + Guild Conquest + templates via multi-field events_full) | 0 | - |
| mhfmsx.bin — Mezeporta Festa | 10 (item names + effects) | 0 confirmed beyond placeholders | - |
| **Total remaining** | | **~0** | |

All known translator-useful text in `client/pc/dat/*.bin` is now extracted. The `.txb` files in the same directory were checked (2026-04-06) and are PNG image containers (or, in the case of `my_garden.txb`, an ECD-wrapped PNG), not text. No remaining extraction work is identified.
