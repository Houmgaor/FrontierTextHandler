"""
Binary file exporter/importer for Monster Hunter Frontier.

Files need to be decrypted and decompressed with a tool like ReFrontier.
"""

import argparse
import logging
import os

import src


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
        prog="FrontierTextConverter",
        description="Converts strings from Monster Hunter Frontier "
        + "between ReFrontier and other formats.",
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
        "Looks for mhfdat.bin, mhfpac.bin, mhfinf.bin in data/ directory.",
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="Compress output file using JKR HFI compression (use with --csv-to-bin).",
    )
    return parser


def main(args: argparse.Namespace) -> None:
    """Main function to read everything."""
    setup_logging(args.verbose)

    if args.extract_all:
        # Batch extraction mode - extract all sections from headers.json
        files = src.extract_all()
        if files:
            print(f"Extracted {len(files)} files to output/")
        else:
            print("No files extracted. Check that data files exist in data/ directory.")
        return

    if not os.path.exists(args.input_file):
        raise FileNotFoundError(
            f"'{args.input_file}' does not exist. You need to import it first."
        )

    if args.refrontier_to_csv:
        src.refrontier_to_csv(args.input_file, args.output_file)
    elif args.csv_to_bin:
        src.import_from_csv(args.input_file, args.output_file, compress=args.compress)
    else:
        # Default: read and save as CSV
        src.extract_from_file(
            args.input_file, args.xpath, args.output_file
        )


if __name__ == "__main__":
    main(parse_inputs().parse_args())
