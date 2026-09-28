"""The optimised codecs must match the original byte-at-a-time ports.

``tests/reference_codecs`` holds the 1.8.0 implementations verbatim. These
tests feed both the same inputs (random, text-like, runs, periodic) at
sizes around the internal block boundaries, and require identical output.
"""

import random
import struct
import unittest

from src.crypto import decode_ecd, encode_ecd
from src.jkr_compress import CompressionType, compress_jkr
from src.jkr_decompress import JKRError, decompress_jkr
from tests.reference_codecs import crypto as ref_crypto
from tests.reference_codecs import jkr_compress as ref_compress
from tests.reference_codecs import jkr_decompress as ref_decompress

# Around the ECD lane count (4096), the prefix-XOR block (65536) and the
# LZ window (8192).
SIZES = [0, 1, 2, 3, 7, 100, 4095, 4096, 4097, 8191, 8192, 8193, 65535, 65536, 65537]


def _samples(rng: random.Random):
    """Yield (label, data) pairs covering the shapes game files have."""
    for size in SIZES:
        words = [rng.randbytes(rng.randint(1, 12)) for _ in range(40)]
        text = b"".join(rng.choice(words) for _ in range(size // 4 + 1))[:size]
        yield f"random-{size}", rng.randbytes(size)
        yield f"text-{size}", text
        yield f"runs-{size}", b"".join(
            bytes([rng.randrange(4)]) * rng.randint(1, 400) for _ in range(size // 50 + 1)
        )[:size]
        yield f"periodic-{size}", (rng.randbytes(rng.randint(1, 9)) * (size + 1))[:size]


class TestEcdMatchesReference(unittest.TestCase):

    def test_encode_and_decode(self):
        rng = random.Random(1)
        for label, data in _samples(rng):
            key = rng.randrange(6)
            with self.subTest(label, key=key):
                encrypted = encode_ecd(data, key)
                self.assertEqual(encrypted, ref_crypto.encode_ecd(data, key))
                self.assertEqual(decode_ecd(encrypted), data)
                self.assertEqual(decode_ecd(encrypted), ref_crypto.decode_ecd(encrypted))


class TestJkrMatchesReference(unittest.TestCase):

    def test_compress_and_decompress(self):
        rng = random.Random(2)
        for label, data in _samples(rng):
            if len(data) > 8193:
                continue  # The reference compressor is slow; skip the largest.
            for kind in (CompressionType.HFIRW, CompressionType.LZ, CompressionType.HFI):
                with self.subTest(label, kind=kind.name):
                    compressed = compress_jkr(data, kind)
                    self.assertEqual(compressed, ref_compress.compress_jkr(data, kind))
                    self.assertEqual(decompress_jkr(compressed), data)

    def test_truncated_lz_stream_decodes_like_reference(self):
        """The game's decoder keeps what it decoded when input runs out."""
        rng = random.Random(3)
        for label, data in _samples(rng):
            if not 100 <= len(data) <= 8193:
                continue
            for kind in (CompressionType.LZ, CompressionType.HFI):
                compressed = ref_compress.compress_jkr(data, kind)
                # Cut inside the payload, past the header and Huffman table.
                payload = 16
                if kind == CompressionType.HFI:
                    root = struct.unpack_from("<h", compressed, 16)[0]
                    payload = 18 + root * 4 - 0x3FC
                cut = compressed[:rng.randrange(payload + 1, len(compressed))]
                with self.subTest(label, kind=kind.name):
                    self.assertEqual(decompress_jkr(cut), ref_decompress.decompress_jkr(cut))

    def test_truncated_huffman_table_is_an_error(self):
        """The reference silently returned zeros, or crashed for type 2."""
        data = b"some text to compress " * 40
        for kind in (CompressionType.HFIRW, CompressionType.HFI):
            compressed = compress_jkr(data, kind)
            with self.subTest(kind=kind.name):
                with self.assertRaises(JKRError):
                    decompress_jkr(compressed[:40])


if __name__ == "__main__":
    unittest.main()
