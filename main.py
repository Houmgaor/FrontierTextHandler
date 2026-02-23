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
        default="dat/armors/head",
        required=False,
        help="Which data to get, as an xpath. "
        + "For instance 'dat/armors/head' to read from mhfDAT.bin ARMORS HELMETS",
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

    if not os.path.exists(args.input_file):
        raise FileNotFoundError(
            f"'{args.input_file}' does not exist. You need to import it first."
        )

    if args.ftxt:
        # FTXT extraction mode
        from src.export import extract_ftxt_file
        csv_path, ref_path = extract_ftxt_file(args.input_file)
        print(f"Extracted FTXT to {csv_path}")
    elif args.quest:
        # Single quest file extraction mode
        from src.export import extract_single_quest_file
        csv_path, ref_path = extract_single_quest_file(args.input_file)
        print(f"Extracted quest text to {csv_path}")
    elif args.refrontier_to_csv:
        src.refrontier_to_csv(args.input_file, args.output_file)
    elif args.csv_to_bin:
        src.import_from_csv(
            args.input_file,
            args.output_file,
            compress=args.compress,
            encrypt=args.encrypt,
            key_index=args.key_index
        )
    else:
        # Default: read and save as CSV
        src.extract_from_file(
            args.input_file, args.xpath, args.output_file
        )


if __name__ == "__main__":
    main(parse_inputs().parse_args())
