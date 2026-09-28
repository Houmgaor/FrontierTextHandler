"""
Map the string tables of mhfpac.bin into headers.json.

    python tools/map_pac_tables.py JP_MHFPAC [--check OTHER_MHFPAC ...] [--write]

The mhfpac.bin header (0x08-0x111C) is a list of table pointers. Each table
ends where the next one starts. A table is added as ``pac/text_<offset>``
when it has one of three shapes:

- *flat*: every non-null word points to the start of a clean string, with
  null padding at most. ``entry_count`` stops at the last string, and
  ``null_padding`` is set when nulls sit between strings, so each string is
  its own row.
- *lists*: the table starts with an index of pointers to null-terminated
  string lists (anywhere in the file), with 0 or small flag values between
  them. It is read with ``record_levels`` (a null-terminated level), one row
  per list; index entries whose list another section reads go in
  ``skip_entries``.
- *records*: fixed-size records up to the first all-zero one, with a single
  field that holds only strings (or 0), read in struct mode.

A table is skipped when it:
- is already (even partly) covered by an existing pac section (flat and
  records tables),
- has fewer than 2 non-empty strings, or they are mostly symbols,
- contains U+FFFD or private-use characters,
- does not read the same (same pointer slots) in every --check file.

Named sections (hunter_navi, help, ...) are mapped by hand; run this after
them so their slots count as covered. Tables of other shapes are reported,
not added. Without --write, nothing is changed.
"""

import argparse
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import common  # noqa: E402
from src.line_length import measure_section_limits  # noqa: E402

HEADER = range(0x08, 0x1120, 4)
BAD = re.compile("[\ufffd\ue000-\uf8ff]")
WORDY = re.compile(r"[\u3040-\u30ff\u4e00-\u9fffA-Za-z0-9%\uff10-\uff5a]")
FLAG = 0x100  # index words below this are flags, not pointers
RECORD_SIZES = (8, 12, 16, 20, 24, 28, 32)


def string_at(data: bytes, pointer: int) -> str | None:
    """The clean string starting at *pointer*, or None."""
    if not (0x100 <= pointer < len(data)) or data[pointer - 1] != 0:
        return None
    end = data.find(b"\0", pointer)
    if end - pointer > 4000:
        return None
    try:
        text = data[pointer:end].decode(common.GAME_ENCODING)
    except UnicodeDecodeError:
        return None
    return text if all(c >= " " or c in "\t\n\x0b" for c in text) else None


def section_slots(data: bytes, config: dict) -> list[int]:
    """Pointer slots a section reads."""
    return [slot for row in common.extract_text_data_from_bytes(data, dict(config))
            for slot in row.get("sub_offsets", [row["offset"]])]


def pac_slots(data: bytes) -> set[int]:
    """Pointer slots already read by a pac section."""
    slots = set()
    for xpath in common.get_all_xpaths():
        if xpath.startswith("pac/"):
            slots.update(section_slots(data, common.read_extraction_config(xpath)))
    return slots


def string_list(data: bytes, pointer: int) -> list[int] | None:
    """Slots of the null-terminated string list at *pointer*, or None."""
    slots = []
    while pointer + 4 * len(slots) + 4 <= len(data):
        slot = pointer + 4 * len(slots)
        word = struct.unpack_from("<I", data, slot)[0]
        if word == 0:
            return slots
        if string_at(data, word) is None:
            return None
        slots.append(slot)
    return None


def list_index(data: bytes, words: list[int]) -> list[list[int] | None]:
    """The leading index of a list-of-lists table: each entry's list slots,
    or None for a flag. Empty if the table does not start with one."""
    index = []
    for word in words:
        if word < FLAG:
            index.append(None)
            continue
        slots = None if word % 4 else string_list(data, word)
        if slots is None:
            break
        index.append(slots)
    while index and index[-1] is None:
        index.pop()
    return index if any(index) else []


def record_field(data: bytes, words: list[int], covered: set[int], table: int):
    """(entry_size, field_offset, count) if the table is records with one
    string field, else None."""
    for size in RECORD_SIZES:
        width = size // 4
        count = 0
        while (count + 1) * width <= len(words) and any(words[count * width:(count + 1) * width]):
            count += 1
        if count < 2:
            continue
        columns = [[words[r * width + f] for r in range(count)] for f in range(width)]
        fields = [f for f, column in enumerate(columns)
                  if all(w == 0 or string_at(data, w) is not None for w in column)
                  and sum(1 for w in column if w) >= 2]
        others = [columns[f] for f in range(width) if f not in fields]
        if len(fields) != 1 or not others or any(
            sum(1 for w in column if string_at(data, w) is not None) > count // 4
            for column in others
        ):
            continue
        field = fields[0]
        if any(table + 4 * (r * width + field) in covered for r in range(count)):
            return None
        return size, 4 * field, count
    return None


def pac_tables(data: bytes):
    """Yield (slot, table, words, string_slots) for every table."""
    header = {o: struct.unpack_from("<I", data, o)[0] for o in HEADER}
    starts = sorted({v for v in header.values() if 0x1000 <= v < len(data)})
    for slot, table in header.items():
        if not 0x1000 <= table < len(data):
            continue
        i = starts.index(table)
        end = min(starts[i + 1] if i + 1 < len(starts) else len(data), len(data))
        words = list(struct.unpack_from(f"<{(end - table) // 4}I", data, table))
        string_slots = [table + 4 * k for k, w in enumerate(words)
                        if w and string_at(data, w) is not None]
        yield slot, table, words, string_slots


def table_config(data: bytes, slot: int, table: int, words: list[int],
                 string_slots: list[int], covered: set[int]):
    """(shape, config) for a table, config None when it is not added."""
    begin = {"begin_pointer": f"0x{slot:X}"}
    flat = list(words)
    while flat and flat[-1] == 0:
        flat.pop()
    if string_slots and all(w == 0 or string_at(data, w) is not None for w in flat):
        if any(s in covered for s in string_slots):
            return "flat", None
        config = {**begin, "entry_count": len(flat)}
        if 0 in flat:
            config["null_padding"] = True
        return "flat", config
    if index := list_index(data, words):
        skip = [i for i, slots in enumerate(index)
                if slots and any(s in covered for s in slots)]
        config = {**begin, "entry_count": len(index), "entry_size": 4,
                  "record_levels": [{"pointer_offset": 0, "entry_size": 4,
                                     "null_terminated": True}]}
        if skip:
            config["skip_entries"] = skip
        return "lists", config
    if found := record_field(data, words, covered, table):
        size, field, count = found
        return "records", {**begin, "entry_count": count, "entry_size": size,
                           "field_offset": field}
    return "other", None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("game_file", help="Unpatched Japanese mhfpac.bin")
    parser.add_argument("--check", nargs="*", default=[],
                        help="Other mhfpac.bin files each table must read the same in")
    parser.add_argument("--write", action="store_true", help="Update src/headers.json")
    args = parser.parse_args()

    data = common.load_file_data(args.game_file)
    others = [common.load_file_data(f) for f in args.check]
    headers_path = ROOT / "src" / "headers.json"
    headers = json.loads(headers_path.read_text(encoding="utf-8"))
    pac = headers["pac"]

    covered = pac_slots(data)
    tables = list(pac_tables(data))
    added, skipped, shapes = [], Counter(), Counter()
    # Flat and records tables own their slots; lists (which may point
    # anywhere) come second and skip the lists those already read.
    for wanted in ({"flat", "records", "other"}, {"lists"}):
        for slot, table, words, string_slots in tables:
            name = f"text_{slot:x}"
            if name in pac or (string_slots and all(s in covered for s in string_slots)):
                continue
            shape, config = table_config(data, slot, table, words, string_slots, covered)
            if shape not in wanted or (shape == "other" and not string_slots):
                continue
            shapes[shape] += 1
            if shape == "other":
                continue
            if add_table(data, others, pac, name, config, covered, skipped):
                added.append((name, pac[name]))

    print(f"tables with uncovered text: {dict(shapes)}")
    print(f"new sections: {len(added)}")
    print(f"skipped tables: {dict(skipped)}")
    if args.write and added:
        # Named sections first, then text_<offset> tables in offset order,
        # so a run from scratch writes the same file.
        tables = sorted((k for k in pac if k.startswith("text_")),
                        key=lambda k: int(k[len("text_"):], 16))
        headers["pac"] = {**{k: v for k, v in pac.items() if not k.startswith("text_")},
                          **{k: pac[k] for k in tables}}
        headers_path.write_text(json.dumps(headers, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8")
        print(f"wrote {headers_path}")


def add_table(data, others, pac, name, config, covered, skipped) -> bool:
    """Check a table's section and add it to *pac*; False if skipped."""
    if config is None:
        skipped["overlaps an existing section"] += 1
        return False
    rows = common.extract_text_data_from_bytes(data, dict(config))
    texts = [t for r in rows for t in r["text"].split("{j}")]
    filled = [t for t in texts if t]
    if len(filled) < 2:
        skipped["fewer than 2 strings"] += 1
        return False
    if any(BAD.search(t) for t in texts):
        skipped["U+FFFD or private-use characters"] += 1
        return False
    if sum(1 for t in filled if WORDY.search(t)) < len(filled) / 2:
        skipped["mostly symbols"] += 1
        return False
    slots = [r.get("sub_offsets", [r["offset"]]) for r in rows]
    try:
        same = all(
            [r.get("sub_offsets", [r["offset"]])
             for r in common.extract_text_data_from_bytes(o, dict(config))] == slots
            for o in others
        )
    except Exception:
        same = False
    if not same:
        skipped["differs in a --check file"] += 1
        return False
    config.update(measure_section_limits(rows))
    pac[name] = config
    covered.update(s for row in slots for s in row)
    return True


if __name__ == "__main__":
    main()
