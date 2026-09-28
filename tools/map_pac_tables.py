"""
Map the flat string tables of mhfpac.bin into headers.json.

    python tools/map_pac_tables.py JP_MHFPAC [--check OTHER_MHFPAC ...] [--write]

The mhfpac.bin header (0x08-0x111C) is a list of table pointers. Each table
ends where the next one starts. A table is added as ``pac/text_<offset>``
when it is a *flat* string list: every non-null word points to the start of
a clean string, with null padding at most. Its ``entry_count`` stops at the
last string, and ``null_padding`` is set when nulls sit between strings, so
each string is its own row.

A table is skipped when it:
- is already (even partly) covered by an existing pac section,
- has fewer than 2 strings, or is mostly symbols,
- contains U+FFFD or private-use characters,
- does not read the same (same pointer slots) in every --check file.

Tables of other shapes (lists of lists, structs) are reported, not added.
Without --write, nothing is changed.
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
BAD = re.compile("[�-]")
WORDY = re.compile(r"[぀-ヿ一-鿿A-Za-z0-9%]")


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
    return text if all(c >= " " or c == "\n" for c in text) else None


def pac_slots(data: bytes) -> set[int]:
    """Pointer slots already read by a pac section."""
    slots = set()
    for xpath in common.get_all_xpaths():
        if xpath.startswith("pac/"):
            config = common.read_extraction_config(xpath)
            for row in common.extract_text_data_from_bytes(data, config):
                slots.update(row.get("sub_offsets", [row["offset"]]))
    return slots


def flat_tables(data: bytes):
    """Yield (slot, shape, count, has_inner_nulls, covers_existing)."""
    header = {o: struct.unpack_from("<I", data, o)[0] for o in HEADER}
    starts = sorted({v for v in header.values() if 0x1000 <= v < len(data)})
    covered = pac_slots(data)
    for slot, table in header.items():
        if not 0x1000 <= table < len(data):
            continue
        i = starts.index(table)
        end = min(starts[i + 1] if i + 1 < len(starts) else len(data), len(data))
        words = list(struct.unpack_from(f"<{(end - table) // 4}I", data, table))
        is_string = [bool(w) and string_at(data, w) is not None for w in words]
        string_slots = [table + 4 * k for k, ok in enumerate(is_string) if ok]
        if not string_slots or all(s in covered for s in string_slots):
            continue
        while words and words[-1] == 0:
            words.pop()
        flat = all(w == 0 or is_string[k] for k, w in enumerate(words))
        yield (slot, "flat" if flat else "other", len(words), 0 in words,
               any(s in covered for s in string_slots))


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

    added, skipped, shapes = [], Counter(), Counter()
    for slot, shape, count, inner_nulls, overlaps in flat_tables(data):
        shapes[shape] += 1
        name = f"text_{slot:x}"
        if shape != "flat":
            continue
        if overlaps:
            skipped["overlaps an existing section"] += 1
            continue
        if name in pac:
            continue
        config = {"begin_pointer": f"0x{slot:X}", "entry_count": count}
        if inner_nulls:
            config["null_padding"] = True
        rows = common.extract_text_data_from_bytes(data, dict(config))
        texts = [r["text"] for r in rows]
        if len(texts) < 2:
            skipped["fewer than 2 strings"] += 1
            continue
        if any(BAD.search(t) for t in texts):
            skipped["U+FFFD or private-use characters"] += 1
            continue
        if sum(1 for t in texts if WORDY.search(t)) < len(texts) / 2:
            skipped["mostly symbols"] += 1
            continue
        offsets = [r["offset"] for r in rows]
        try:
            same = all(
                [r["offset"] for r in common.extract_text_data_from_bytes(o, dict(config))] == offsets
                for o in others
            )
        except Exception:
            same = False
        if not same:
            skipped["differs in a --check file"] += 1
            continue
        config.update(measure_section_limits(rows))
        pac[name] = config
        added.append((name, len(rows)))

    print(f"tables with uncovered text: {dict(shapes)}")
    print(f"new sections: {len(added)} ({sum(n for _, n in added)} rows)")
    print(f"skipped flat tables: {dict(skipped)}")
    if args.write and added:
        headers_path.write_text(json.dumps(headers, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8")
        print(f"wrote {headers_path}")


if __name__ == "__main__":
    main()
