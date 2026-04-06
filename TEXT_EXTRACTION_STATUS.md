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

All documented text fields in mhfpac.bin are now extracted. Grouped sections (`text_14`..`text_54`) emit multi-string CSV rows joined with `<join at="N">` tags and require `--xpath=pac/text_XX` on `csv-to-bin` so `rebuild_section` is used.

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
| `gao/dialogue_type_0` | 0x90 | Felyne partner dialogue template, personality 0 — 40 lines | null-terminated |
| `gao/dialogue_type_1` | 0x94 | Felyne partner dialogue template, personality 1 — 40 lines | null-terminated |
| `gao/dialogue_type_2` | 0x98 | Felyne partner dialogue template, personality 2 — 40 lines | null-terminated |
| `gao/dialogue_type_3` | 0x9C | Felyne partner dialogue template, personality 3 — 40 lines | null-terminated |
| `gao/dialogue_type_4` | 0xA0 | Felyne partner dialogue template, personality 4 — 40 lines | null-terminated |
| `gao/dialogue_type_5` | 0xA4 | Felyne partner dialogue template, personality 5 — 40 lines | null-terminated |
| `gao/dialogue_type_6` | 0xA8 | Felyne partner dialogue template, personality 6 — 40 lines | null-terminated |
| `gao/dialogue_type_7` | 0xAC | Felyne partner dialogue template, personality 7 — 40 lines | null-terminated |

**834 strings** extracted across 10 header-rooted pointer tables. The 8 dialogue templates are indexed by Felyne personality type and each contain 40 parallel lines (greetings, quest departure, reactions, etc.).

Note: `armor_helm` uses fixed entry_count because a literal ASCII build-date string ("YYYY/MM/DD") is stored between the table end and its 0 terminator, which breaks null-terminated scanning. The other 9 tables have clean 0-terminators.

### Not yet extracted

Several larger tables exist but are reached indirectly through meta-tables at 0xC640/0xC660/0xC680 that store (begin, end) pointer pairs — these need struct-level reverse engineering of the meta-table layout:

| Pointer | Evidence | Est. strings | Notes |
|---------|----------|-------------|-------|
| 0x020 | header → 0x30CC0, first entry "Nothing equipped." | ~670 | Felyne equipment descriptions (sparse, many zero-ptr holes) |
| 0x028 | header → 0x22A80, entries like "レイアネコレイピア" | ~97 | Felyne weapon names |
| 0x02C | header → 0x26320, first entry "Nothing equipped." | ~1032 | Felyne weapon descriptions (sparse) |
| 0x040 | header → 0x21FE0, Felyne quest intro lines | ~68 | Partner situational dialogue |
| orphan 0x13EC8 | 54 Felyne skill descriptions | 54 | No header xref found; likely indexed via 0x0CC/0x0D4/0x0DC triplets |

Remaining unextracted text in mhfgao.bin: **~1,900 strings** (estimate, needs validated struct layout before safe round-trip is possible).

---

## Other game files

### With text (undocumented structure)

These files contain readable text but have **no ImHex patterns or format documentation**. Their pointer table structures would need to be reverse-engineered before extraction can be implemented.

| File | Size (decrypted) | Content | Est. strings | Difficulty |
|------|-----------------|---------|-------------|------------|
| `mhfsqd.bin` | 16,036 B | NPC partner names (Aaron, Tania, etc.) + squad labels | ~230 | HARD — no docs |
| `mhfrcc.bin` | 2,556 B | Event/festival announcement text | 21 | HARD — no docs, small file |
| `mhfmsx.bin` | 15,072 B | Tower/festival item names and effect labels | ~10 | HARD — no docs, mostly numeric |

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
| mhfgao.bin — Felyne | 834 (armor + dialogue) | ~1,900 (equipment descriptions, weapons, orphan tables) | Meta-table (0xC640-0xC680) struct RE |
| Undocumented files | 0 | ~260 (mhfsqd, mhfrcc, mhfmsx) | No format documentation |
| **Total remaining** | | **~2,160** | |

### Recommended next steps (by effort/impact ratio)

1. **mhfgao.bin remainder** — RE the meta-tables at 0xC640/0xC660/0xC680 to surface equipment description and weapon tables (~1,900 strings)
2. **Undocumented files** (mhfsqd, mhfrcc, mhfmsx) — require reverse engineering before implementation
