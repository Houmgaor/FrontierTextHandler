"""
Binary file exporter/importer for Monster Hunter Frontier.

Supports automatic decryption (ECD/EXF) and decompression (JPK/JKR).
"""

import argparse
import logging
import os

import src
from src import __version__


def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging for the application.

    :param verbose: If True, set DEBUG level; otherwise INFO level
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s"
    )


def parse_inputs() -> argparse.ArgumentParser:
    """Parse console arguments."""
    parser = argparse.ArgumentParser(
        prog="FrontierTextHandler",
        description="Extract, edit, and reimport text from Monster Hunter Frontier game files.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "input_file", type=str, default="data/mhfdat.bin", nargs="?", help="Input file."
    )
    parser.add_argument(
        "output_file",
        type=str,
        default="output/minimal.csv",
        nargs="?",
        help="Output file name.",
    )
    parser.add_argument(
        "--xpath",
        type=str,
        default=None,
        required=False,
        help="Which data to get, as an xpath. "
        + "For instance 'dat/armors/head' to read from mhfDAT.bin ARMORS HELMETS. "
        + "When used with --csv-to-bin, enables in-place section rebuild.",
    )
    parser.add_argument(
        "--refrontier-to-csv",
        action="store_true",
        help="Convert from ReFrontier format (TSV, Shift-JIS) to CSV format.",
    )
    parser.add_argument(
        "--csv-to-bin",
        action="store_true",
        help="Convert from a CSV file (UTF-8) to your binary file.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (debug) output.",
    )
    parser.add_argument(
        "--extract-all",
        action="store_true",
        help="Extract all sections defined in headers.json. "
        "Looks for mhfdat.bin, mhfpac.bin, mhfinf.bin, mhfjmp.bin, mhfnav.bin in data/ directory.",
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="Compress output file using JKR HFI compression (use with --csv-to-bin).",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt output file using ECD encryption (use with --csv-to-bin).",
    )
    parser.add_argument(
        "--key-index",
        type=int,
        default=4,
        choices=range(6),
        metavar="0-5",
        help="ECD key index to use for encryption (default: 4). All MHF files use key 4.",
    )
    parser.add_argument(
        "--fold-unsupported-chars",
        action="store_true",
        help="Fold characters the MHF custom font cannot render (Latin "
        "diacritics, ligatures, typographic punctuation) down to ASCII "
        "before encoding. Use with --csv-to-bin when importing European "
        "languages whose source CSVs contain accents (e.g. French é è à "
        "ç œ « »). Off by default so Japanese imports stay byte-identical. "
        "Remove once the in-game font is extended to cover the missing glyphs.",
    )
    parser.add_argument(
        "--ftxt",
        action="store_true",
        help="Extract text from an FTXT standalone text file (magic 0x000B0000).",
    )
    parser.add_argument(
        "--quest",
        action="store_true",
        help="Extract text from a standalone quest .bin file.",
    )
    parser.add_argument(
        "--quest-dir",
        type=str,
        metavar="DIR",
        help="Batch extract text from all quest .bin files in a directory.",
    )
    parser.add_argument(
        "--npc",
        action="store_true",
        help="Extract NPC dialogue from a stage dialogue binary file.",
    )
    parser.add_argument(
        "--npc-dir",
        type=str,
        metavar="DIR",
        help="Batch extract NPC dialogue from all .bin files in a directory.",
    )
    parser.add_argument(
        "--npc-to-bin",
        action="store_true",
        help="Import NPC dialogue translations from CSV back to binary (full rebuild).",
    )
    parser.add_argument(
        "--scenario",
        action="store_true",
        help="Extract text from a scenario .bin file (story system).",
    )
    parser.add_argument(
        "--scenario-dir",
        type=str,
        metavar="DIR",
        help="Batch extract text from all scenario .bin files in a directory.",
    )
    parser.add_argument(
        "--scenario-to-bin",
        action="store_true",
        help="Import scenario translations from CSV or JSON back to binary (in-place patch).",
    )
    parser.add_argument(
        "--diff",
        type=str,
        metavar="FILE_B",
        help="Compare strings between input_file (A) and FILE_B (B). "
        "Works with CSV and binary files. Binary files require --xpath, --ftxt, --quest, --npc, or --scenario.",
    )
    parser.add_argument(
        "--merge",
        type=str,
        metavar="NEW_CSV",
        help="Merge translations from input_file (old translated CSV/JSON) into NEW_CSV "
        "(freshly extracted). Carries over translations where source is unchanged.",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate a game file and report its structure (encryption, compression, format).",
    )
    parser.add_argument(
        "--list-xpaths",
        action="store_true",
        help="List all available extraction paths from headers.json.",
    )
    parser.add_argument(
        "--decrypt",
        type=str,
        metavar="FILE",
        help="Decrypt an ECD/EXF file and write to output. Use with output_file argument.",
    )
    parser.add_argument(
        "--apply-translations",
        action="store_true",
        help=(
            "Apply a MHFrontier-Translation release JSON (input_file) to the game "
            "directory given by --game-dir.  Requires --lang and --game-dir. "
            "Use --compress and --encrypt to produce game-ready files."
        ),
    )
    parser.add_argument(
        "--lang",
        type=str,
        default="fr",
        metavar="CODE",
        help="Language code to apply with --apply-translations (default: fr).",
    )
    parser.add_argument(
        "--game-dir",
        type=str,
        default=None,
        metavar="DIR",
        help="Root directory of the game installation (required by --apply-translations).",
    )
    parser.add_argument(
        "--legacy-offset",
        action="store_true",
        help=(
            "Emit the legacy offset-keyed CSV/JSON format "
            "(``location,source,target`` with a ``0xNNN@file.bin`` "
            "first column) instead of the 1.6.0 default index-keyed "
            "format (``index,source,target``). Use this only if you "
            "need to interoperate with tooling that hasn't yet "
            "adopted the index format; the importer accepts both "
            "forms either way."
        ),
    )
    parser.add_argument(
        "--with-index",
        action="store_true",
        help=argparse.SUPPRESS,  # no-op alias: 1.5.0 opt-in is the default in 1.6.0+
    )
    parser.add_argument(
        "--validate-placeholders",
        type=str,
        metavar="FILE",
        help=(
            "Lint a translation CSV/JSON: check that every row preserves "
            "its inline placeholders ({cNN}/{/c}, {j}, {K...}, {i...}, "
            "{u...}) between source and target. Prints a report and "
            "exits non-zero when any row has a mismatch. No binary is "
            "touched, so this is safe to run in CI on every commit to a "
            "translation repository."
        ),
    )
    parser.add_argument(
        "--strict-placeholders",
        action="store_true",
        help=(
            "Treat placeholder mismatches as hard errors during import. "
            "By default the importers log a warning summary and proceed; "
            "with this flag the first bad row aborts the import so CI "
            "pipelines can fail a build on malformed translations."
        ),
    )
    parser.add_argument(
        "--measure-line-lengths",
        action="store_true",
        help=(
            "Extract every section from the game binaries, measure the "
            "maximum display width and sub-string count per section, "
            "and write the results into headers.json. Run this once "
            "on the original Japanese binaries to populate the limits "
            "that --validate-line-lengths and the import-time checks use."
        ),
    )
    parser.add_argument(
        "--validate-line-lengths",
        type=str,
        metavar="FILE",
        help=(
            "Lint a translation CSV/JSON: check that every translated "
            "row's display width stays within the section's measured "
            "limit (from headers.json). Prints a report and exits "
            "non-zero when any row exceeds the limit. Run "
            "--measure-line-lengths first to populate the limits."
        ),
    )
    parser.add_argument(
        "--strict-line-lengths",
        action="store_true",
        help=(
            "Treat display-width violations as hard errors during "
            "import. By default the importers log a warning summary "
            "and proceed; with this flag the first violation aborts "
            "the import."
        ),
    )
    parser.add_argument(
        "--max-expansion",
        type=float,
        default=1.0,
        metavar="N",
        help=(
            "Multiplier on the measured max_display_width when "
            "validating line lengths. Default 1.0 (no expansion "
            "allowed beyond the original Japanese strings). "
            "Use e.g. 1.1 for 10%% slack."
        ),
    )
    parser.add_argument(
        "--save-meta",
        action="store_true",
        help="Save .meta file when decrypting (preserves header for re-encryption).",
    )
    parser.add_argument(
        "--game-version",
        type=str,
        default="zz",
        metavar="VERSION",
        help=(
            "Game version key for versioned entry_count maps in "
            "headers.json. Default: 'zz' (MHF ZZ). Other versions "
            "use different array sizes. The tool auto-detects the "
            "version when possible."
        ),
    )
    return parser


def main(args: argparse.Namespace) -> None:
    """Main function to read everything."""
    setup_logging(args.verbose)

    if args.list_xpaths:
        from src.common import get_all_xpaths, read_extraction_config
        xpaths = get_all_xpaths()
        print(f"Available extraction paths ({len(xpaths)}):\n")
        for xpath in xpaths:
            config = read_extraction_config(xpath)
            # Determine extraction mode
            if config.get("quest_table"):
                mode = "quest_table"
            elif config.get("null_terminated"):
                mode = "null_terminated"
                if config.get("grouped_entries"):
                    mode += "+grouped"
            elif "count_base_pointer" in config and "entry_size" in config:
                mode = "indirect_strided"
            elif "count_base_pointer" in config:
                mode = "indirect_flat"
            elif "count_pointer" in config:
                mode = "count_based"
            elif "entry_count" in config:
                mode = "struct_strided"
            else:
                mode = "pointer_pair"
            print(f"  {xpath}  ({mode})")
        return

    if args.validate:
        result = src.validate_file(args.input_file)
        print(f"File: {result.file_path} ({result.file_size:,} bytes)")
        if result.layers:
            print("Layers:")
            for i, layer in enumerate(result.layers, 1):
                print(f"  {i}. {layer}")
        if result.error:
            print(f"  ERROR: {result.error}")
        print(f"Format: {result.inner_format}")
        print(f"Status: {'OK' if result.valid else 'INVALID'}")
        return

    if args.validate_placeholders:
        # Standalone lint — read a translation CSV/JSON and report
        # every placeholder mismatch between source and target without
        # touching any binary. Exits non-zero when there is at least
        # one issue so CI pipelines can gate merges on it.
        validator = src.validate_translation_file(args.validate_placeholders)
        if validator.issue_count == 0:
            print(f"OK: no placeholder mismatches in {args.validate_placeholders}")
            return
        print(
            f"FAIL: {validator.issue_count} row(s) in "
            f"{args.validate_placeholders} have placeholder mismatches:"
        )
        for row_id, issues in validator.rows:
            for issue in issues:
                print(f"  {row_id}: {issue.describe()}")
        raise SystemExit(1)

    if args.measure_line_lengths:
        from src.line_length import measure_all_sections, update_headers_with_limits
        print("Measuring display-width limits from original binaries...")
        limits = measure_all_sections()
        if not limits:
            print("No sections measured. Are the game binaries in data/?")
            return
        count = update_headers_with_limits(limits)
        print(f"Updated {count} section(s) in headers.json with "
              "max_display_width and max_sub_count.")
        return

    if args.validate_line_lengths:
        from src.line_length import validate_translation_file_line_lengths
        validator = validate_translation_file_line_lengths(
            args.validate_line_lengths,
            xpath=args.xpath,
            margin=args.max_expansion,
        )
        if validator.issue_count == 0:
            print(f"OK: no line-length violations in {args.validate_line_lengths}")
            return
        print(
            f"FAIL: {validator.issue_count} row(s) in "
            f"{args.validate_line_lengths} exceed display-width limits:"
        )
        for row_id, issues in validator.rows:
            for issue in issues:
                print(f"  {row_id}: {issue.describe()}")
        raise SystemExit(1)

    if args.diff:
        from src.diff import load_strings, diff_strings, format_diff

        # Determine extraction mode from flags
        if args.xpath:
            mode = "xpath"
        elif args.ftxt:
            mode = "ftxt"
        elif args.quest:
            mode = "quest"
        elif args.npc:
            mode = "npc"
        elif args.scenario:
            mode = "scenario"
        else:
            mode = None  # CSV files don't need a mode

        file_a = args.input_file
        file_b = args.diff

        for f in (file_a, file_b):
            if not os.path.exists(f):
                raise FileNotFoundError(f"'{f}' does not exist.")

        strings_a = load_strings(file_a, mode=mode, xpath=args.xpath)
        strings_b = load_strings(file_b, mode=mode, xpath=args.xpath)
        result = diff_strings(strings_a, strings_b, file_a, file_b)
        print(format_diff(result))
        return

    if args.merge:
        from src.merge import merge_translations, write_merged, format_merge_report

        old_file = args.input_file
        new_file = args.merge

        for f in (old_file, new_file):
            if not os.path.exists(f):
                raise FileNotFoundError(f"'{f}' does not exist.")

        # Determine output path
        if args.output_file != "output/minimal.csv":
            output_path = args.output_file
        elif new_file.lower().endswith(".json"):
            output_path = "output/merged.json"
        else:
            output_path = "output/merged.csv"

        result, rows = merge_translations(old_file, new_file)
        count = write_merged(rows, output_path, source_file=os.path.basename(new_file))
        print(format_merge_report(result))
        print(f"\nWrote {count} entries to {output_path}")
        return

    if args.decrypt:
        # Decrypt mode
        if not os.path.exists(args.decrypt):
            raise FileNotFoundError(f"'{args.decrypt}' does not exist.")

        with open(args.decrypt, "rb") as f:
            encrypted_data = f.read()

        if not src.is_encrypted_file(encrypted_data):
            raise ValueError(f"'{args.decrypt}' is not an ECD or EXF encrypted file.")

        decrypted_data, header = src.decrypt(encrypted_data)

        # Determine output path
        output_path = args.output_file if args.output_file != "output/minimal.csv" else args.decrypt + ".decd"

        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        print(f"Decrypted {args.decrypt} -> {output_path}")

        if args.save_meta:
            meta_path = output_path + ".meta"
            with open(meta_path, "wb") as f:
                f.write(header)
            print(f"Saved header to {meta_path}")

        return

    # Index-keyed CSV/JSON is the 1.6.0 default; ``--legacy-offset``
    # opts back into the pre-1.6.0 ``location,source,target`` shape.
    # ``--with-index`` is accepted as a silent no-op alias so scripts
    # written against 1.5.0 keep working.
    with_index = not args.legacy_offset

    if args.extract_all:
        # Batch extraction mode - extract all sections from headers.json
        files = src.extract_all(with_index=with_index, game_version=args.game_version)
        if files:
            print(f"Extracted {len(files)} files to output/")
        else:
            print("No files extracted. Check that data files exist in data/ directory.")
        return

    if args.quest_dir:
        # Batch quest extraction mode
        from src.export import extract_quest_files
        files = extract_quest_files(args.quest_dir, with_index=with_index)
        if files:
            print(f"Extracted {len(files)} quest files to output/")
        else:
            print("No quest files extracted.")
        return

    if args.npc_dir:
        # Batch NPC dialogue extraction mode
        from src.export import extract_npc_dialogue_files
        files = extract_npc_dialogue_files(args.npc_dir, with_index=with_index)
        if files:
            print(f"Extracted {len(files)} NPC dialogue files to output/")
        else:
            print("No NPC dialogue files extracted.")
        return

    if args.scenario_dir:
        # Batch scenario extraction mode
        from src.export import extract_scenario_files
        files = extract_scenario_files(args.scenario_dir, with_index=with_index)
        if files:
            print(f"Extracted {len(files)} scenario files to output/")
        else:
            print("No scenario files extracted.")
        return

    if not os.path.exists(args.input_file):
        raise FileNotFoundError(
            f"'{args.input_file}' does not exist. You need to import it first."
        )

    if args.scenario_to_bin:
        # Scenario import mode
        src.import_scenario_from_csv(
            args.input_file,
            args.output_file,
            compress=args.compress,
            encrypt=args.encrypt,
            key_index=args.key_index,
            strict_placeholders=args.strict_placeholders,
        )
    elif args.scenario:
        # Single scenario extraction mode
        from src.export import extract_scenario_file
        csv_path, ref_path, json_path = extract_scenario_file(
            args.input_file, with_index=with_index,
        )
        print(f"Extracted scenario text to {csv_path}")
    elif args.npc_to_bin:
        # NPC dialogue import mode
        src.import_npc_dialogue_from_csv(
            args.input_file,
            args.output_file,
            compress=args.compress,
            encrypt=args.encrypt,
            key_index=args.key_index,
            strict_placeholders=args.strict_placeholders,
        )
    elif args.npc:
        # Single NPC dialogue extraction mode
        from src.export import extract_npc_dialogue_file
        csv_path, ref_path, json_path = extract_npc_dialogue_file(
            args.input_file, with_index=with_index,
        )
        print(f"Extracted NPC dialogue to {csv_path}")
    elif args.ftxt:
        # FTXT extraction mode
        from src.export import extract_ftxt_file
        csv_path, ref_path, json_path = extract_ftxt_file(
            args.input_file, with_index=with_index,
        )
        print(f"Extracted FTXT to {csv_path}")
    elif args.quest:
        # Single quest file extraction mode
        from src.export import extract_single_quest_file
        csv_path, ref_path, json_path = extract_single_quest_file(
            args.input_file, with_index=with_index,
        )
        print(f"Extracted quest text to {csv_path}")
    elif args.refrontier_to_csv:
        src.refrontier_to_csv(args.input_file, args.output_file)
    elif args.apply_translations:
        if not args.game_dir:
            raise SystemExit("--apply-translations requires --game-dir <path>")
        from src.import_data import apply_translations_from_release_json
        results = apply_translations_from_release_json(
            json_file=args.input_file,
            lang=args.lang,
            game_dir=args.game_dir,
            compress=args.compress,
            encrypt=args.encrypt,
            key_index=args.key_index,
            strict_placeholders=args.strict_placeholders,
            game_version=args.game_version,
        )
        if results:
            total = sum(results.values())
            print(f"\n✓ Applied {total} string(s) across {len(results)} file(s):")
            for rel_path, count in sorted(results.items()):
                print(f"  {count:>6}  {rel_path}")
        else:
            print("No translations applied (no matching game files found or no translated strings).")
    elif args.csv_to_bin:
        src.import_from_csv(
            args.input_file,
            args.output_file,
            compress=args.compress,
            encrypt=args.encrypt,
            key_index=args.key_index,
            xpath=args.xpath,
            fold_unsupported_chars=args.fold_unsupported_chars,
            strict_placeholders=args.strict_placeholders,
            game_version=args.game_version,
        )
    else:
        # Default: read and save as CSV
        xpath = args.xpath if args.xpath is not None else "dat/armors/head"
        src.extract_from_file(
            args.input_file, xpath, args.output_file,
            with_index=with_index,
            game_version=args.game_version,
        )


if __name__ == "__main__":
    main(parse_inputs().parse_args())
