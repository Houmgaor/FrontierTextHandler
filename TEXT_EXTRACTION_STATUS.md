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

### Not yet extracted

Important context: mhfpac uses a `nums` table (pointer at 0x10) similar to mhfdat's `important_nums`. Counts for many sections are stored as `u16` values at offsets within that table. The decompile pattern references these as `hd_dll_afaf5e + offset`.

| Pointer | Content | Est. count | Structure | Difficulty |
|---------|---------|-----------|-----------|------------|
| 0x14 | UI labels group A (e.g. "Status") | variable | `s32pxT<3>` — 3 string pointers per entry, null-terminated array | MEDIUM — grouped strings, null-terminated |
| 0x18 | UI labels group B (e.g. "Discard") | variable | `s32pxT<4>` — 4 strings per entry | MEDIUM |
| 0x1C | UI labels group C | variable | `s32pxT<5>` — 5 strings per entry | MEDIUM |
| 0x20 | UI labels group D | variable | `s32pxT<3>` — 3 strings per entry | MEDIUM |
| 0x24 | Quest/status screen labels ("Quest Name:", etc.) | variable | `s32pxT<19>` — 19 strings per entry | MEDIUM |
| 0x28 | Menu labels A ("Item", etc.) | variable | `s32pxT<8>` — 8 strings per entry | MEDIUM |
| 0x2C | Menu labels B | variable | `s32pxT<10>` — 10 strings per entry | MEDIUM |
| 0x30 | Settings/options labels ("Hide HUD", etc.) | variable | `s32pxT<92>` — 92 strings per entry (marked TODO in pattern) | HARD — very large groups, pattern notes inaccuracy |
| 0x34 | Toggle labels ("ON", etc.) | variable | `s32pxT<4>` — 4 strings per entry | MEDIUM |
| 0x40 | Loading screen text ("Loading World Select.") | small | `struct { padding[4]; s32p; }` — 8 bytes per entry | MEDIUM — strided with padding |
| 0x44 | Felyne Elder dialogue | small | Same structure as 0x40 | MEDIUM |
| 0x48 | Skill tree / decoration name pairs | 423 (0x1A7) | `s32pxT<2>` — 2 strings per entry, fixed count | MEDIUM — could use flat pointer-pair if paired |
| 0x50 | Additional skill names A | variable | `s32pxT<2>` — null-terminated | MEDIUM |
| 0x54 | Additional skill names B | variable | `s32pxT<2>` — null-terminated | MEDIUM |
| 0x60 | Controller labels: Frontier Type | counted | `varPaddT<s32p, 0xC>` — s32p + 12 bytes padding (16 per entry). Count from nums+0x22. | MEDIUM — strided extraction |
| 0x64 | Controller labels: Attack Type | counted | Same structure. Count from nums+0x24. | MEDIUM |
| 0x68 | Controller labels: Classic Type | counted | Same structure. Count from nums+0x26. | MEDIUM |
| 0x6C | Controller labels: Common Actions | counted | Same structure. Count from nums+0x28. | MEDIUM |
| 0x94 | Character customization ("Change hair color", etc.) | counted | `struct { padding[4]; s32p; s32p; padding[4]; }` — 16 bytes per entry, 2 strings. Count from nums+0x1C. | MEDIUM — strided with 2 fields |
| 0xC8 | Partner dialogue A (Felyne shop) | counted | `varPaddT<s32p, 0x8>` — s32p + 8 bytes padding (12 per entry). Count from nums+0x52. | MEDIUM — strided |
| 0xCC | Partner dialogue B (quest departure) | counted | Same structure. Count from nums+0x54. | MEDIUM |
| 0xD0 | Partner dialogue C (NPC speech) | counted | Same structure. Count from nums+0x5A. | MEDIUM |
| 0xD4 | Partner dialogue D (Felyne speech) | counted | Same structure. Count from nums+0x5C. | MEDIUM |

Note on `s32pxT<N>`: These are groups of N consecutive `s32p` pointers treated as one logical entry. The null-terminated variants (`while(read_signed($,4)!=0)`) scan until a zero pointer marks the end. These can be treated as flat pointer tables if we don't need to preserve the grouping, since `read_file_section` already handles contiguous pointer arrays.

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

### With text (undocumented structure)

These files contain readable text but have **no ImHex patterns or format documentation**. Their pointer table structures would need to be reverse-engineered before extraction can be implemented.

| File | Size (decrypted) | Content | Est. strings | Difficulty |
|------|-----------------|---------|-------------|------------|
| `mhfgao.bin` | 218,981 B | Companion/Felyne skill names, descriptions, quest dialogue | ~2,186 | HARD — no docs |
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
| mhfpac.bin — UI/dialogue | 0 | ~hundreds (menus, labels, NPC dialogue) | `s32pxT<N>` grouped strings, padded structs |
| mhfjmp.bin | 53 | 0 | - |
| mhfinf.bin — quests | **~22,700** | 0 | - |
| Undocumented files | 0 | ~2,450 (mhfgao, mhfsqd, mhfrcc, mhfmsx) | No format documentation |
| **Total remaining** | | **~2,500+** | |

### Recommended next steps (by effort/impact ratio)

1. **mhfpac.bin UI labels** (0x14-0x34) — treat `s32pxT<N>` as flat pointer tables using null-terminated mode
2. **mhfpac.bin strided sections** (0x40-0xD4) — use indirect-count strided mode
3. **Undocumented files** — require reverse engineering before implementation
