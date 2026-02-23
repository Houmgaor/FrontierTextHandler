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
        "--diff",
        type=str,
        metavar="FILE_B",
        help="Compare strings between input_file (A) and FILE_B (B). "
        "Works with CSV and binary files. Binary files require --xpath, --ftxt, --quest, or --npc.",
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
        "--decrypt",
        type=str,
        metavar="FILE",
        help="Decrypt an ECD/EXF file and write to output. Use with output_file argument.",
    )
    parser.add_argument(
        "--save-meta",
        action="store_true",
        help="Save .meta file when decrypting (preserves header for re-encryption).",
    )
    return parser


def main(args: argparse.Namespace) -> None:
    """Main function to read everything."""
    setup_logging(args.verbose)

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

    if args.extract_all:
        # Batch extraction mode - extract all sections from headers.json
        files = src.extract_all()
        if files:
            print(f"Extracted {len(files)} files to output/")
        else:
            print("No files extracted. Check that data files exist in data/ directory.")
        return

    if args.quest_dir:
        # Batch quest extraction mode
        from src.export import extract_quest_files
        files = extract_quest_files(args.quest_dir)
        if files:
            print(f"Extracted {len(files)} quest files to output/")
        else:
            print("No quest files extracted.")
        return

    if args.npc_dir:
        # Batch NPC dialogue extraction mode
        from src.export import extract_npc_dialogue_files
        files = extract_npc_dialogue_files(args.npc_dir)
        if files:
            print(f"Extracted {len(files)} NPC dialogue files to output/")
        else:
            print("No NPC dialogue files extracted.")
        return

    if not os.path.exists(args.input_file):
        raise FileNotFoundError(
            f"'{args.input_file}' does not exist. You need to import it first."
        )

    if args.npc_to_bin:
        # NPC dialogue import mode
        src.import_npc_dialogue_from_csv(
            args.input_file,
            args.output_file,
            compress=args.compress,
            encrypt=args.encrypt,
            key_index=args.key_index,
        )
    elif args.npc:
        # Single NPC dialogue extraction mode
        from src.export import extract_npc_dialogue_file
        csv_path, ref_path, json_path = extract_npc_dialogue_file(args.input_file)
        print(f"Extracted NPC dialogue to {csv_path}")
    elif args.ftxt:
        # FTXT extraction mode
        from src.export import extract_ftxt_file
        csv_path, ref_path, json_path = extract_ftxt_file(args.input_file)
        print(f"Extracted FTXT to {csv_path}")
    elif args.quest:
        # Single quest file extraction mode
        from src.export import extract_single_quest_file
        csv_path, ref_path, json_path = extract_single_quest_file(args.input_file)
        print(f"Extracted quest text to {csv_path}")
    elif args.refrontier_to_csv:
        src.refrontier_to_csv(args.input_file, args.output_file)
    elif args.csv_to_bin:
        src.import_from_csv(
            args.input_file,
            args.output_file,
            compress=args.compress,
            encrypt=args.encrypt,
            key_index=args.key_index,
            xpath=args.xpath,
        )
    else:
        # Default: read and save as CSV
        xpath = args.xpath if args.xpath is not None else "dat/armors/head"
        src.extract_from_file(
            args.input_file, xpath, args.output_file
        )


if __name__ == "__main__":
    main(parse_inputs().parse_args())
