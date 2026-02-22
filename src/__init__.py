"""
Definition of the FrontierTextHandler module.
"""

__version__ = "1.0.0"

from .export import extract_from_file, extract_all
from .transform import refrontier_to_csv
from .import_data import import_from_csv, CSVParseError
from .common import (
    EncodingError,
    encode_game_string,
    decode_game_string,
    GAME_ENCODING,
    load_file_data,
    read_extraction_config,
    extract_text_data,
)
from .binary_file import InvalidPointerError
from .jkr_decompress import decompress_jkr, is_jkr_file, CompressionType, JKRError
from .jkr_compress import compress_jkr, compress_jkr_hfi, compress_jkr_raw
from .crypto import (
    CryptoError,
    is_ecd_file,
    is_exf_file,
    is_encrypted_file,
    decode_ecd,
    encode_ecd,
    decode_exf,
    encode_exf,
    decrypt,
    encrypt,
)
