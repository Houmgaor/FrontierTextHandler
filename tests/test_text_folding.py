"""Tests for src.text_folding."""
import unittest

from src.text_folding import fold_unsupported_chars


class TestFoldUnsupportedChars(unittest.TestCase):
    """The folding pass replaces glyphs the MHF custom font cannot render."""

    def test_french_lowercase_accents(self) -> None:
        self.assertEqual(fold_unsupported_chars("Méga potion"), "Mega potion")
        self.assertEqual(fold_unsupported_chars("Drogue du démon"), "Drogue du demon")
        self.assertEqual(
            fold_unsupported_chars("Sérum psychique"), "Serum psychique"
        )
        self.assertEqual(fold_unsupported_chars("brûlée"), "brulee")

    def test_french_uppercase_accents(self) -> None:
        self.assertEqual(fold_unsupported_chars("Épée"), "Epee")
        self.assertEqual(fold_unsupported_chars("À TOI"), "A TOI")
        self.assertEqual(fold_unsupported_chars("ÇA VA"), "CA VA")

    def test_oe_ligature(self) -> None:
        self.assertEqual(fold_unsupported_chars("cœur"), "coeur")
        self.assertEqual(fold_unsupported_chars("Œuvre"), "Oeuvre")

    def test_ae_ligature(self) -> None:
        self.assertEqual(fold_unsupported_chars("cæsar"), "caesar")

    def test_french_quotation_marks(self) -> None:
        self.assertEqual(fold_unsupported_chars("« Épée »"), '" Epee "')

    def test_typographic_punctuation(self) -> None:
        self.assertEqual(fold_unsupported_chars("c'est"), "c'est")  # straight apostrophe untouched
        self.assertEqual(fold_unsupported_chars("c\u2019est"), "c'est")  # curly → straight
        self.assertEqual(fold_unsupported_chars("etc\u2026"), "etc...")  # ellipsis
        self.assertEqual(
            fold_unsupported_chars("ouvre\u2014ferme"), "ouvre-ferme"
        )  # em dash

    def test_non_breaking_spaces(self) -> None:
        self.assertEqual(fold_unsupported_chars("a\u00a0b"), "a b")
        self.assertEqual(fold_unsupported_chars("a\u202fb"), "a b")

    def test_japanese_unchanged(self) -> None:
        # Japanese strings must round-trip untouched.
        self.assertEqual(fold_unsupported_chars("回復薬"), "回復薬")
        self.assertEqual(fold_unsupported_chars("回復薬グレート"), "回復薬グレート")
        self.assertEqual(fold_unsupported_chars("武器"), "武器")

    def test_ascii_unchanged(self) -> None:
        self.assertEqual(fold_unsupported_chars("Potion"), "Potion")
        self.assertEqual(fold_unsupported_chars(""), "")
        self.assertEqual(
            fold_unsupported_chars("Hello, World! 123"), "Hello, World! 123"
        )

    def test_mixed_string(self) -> None:
        self.assertEqual(
            fold_unsupported_chars("Méga potion (回復薬グレート)"),
            "Mega potion (回復薬グレート)",
        )

    def test_german_eszett(self) -> None:
        self.assertEqual(fold_unsupported_chars("Straße"), "Strasse")

    def test_other_european_diacritics(self) -> None:
        # Spanish, Portuguese, Nordic — all should fold to ASCII base.
        self.assertEqual(fold_unsupported_chars("año"), "ano")
        self.assertEqual(fold_unsupported_chars("São Paulo"), "Sao Paulo")
        self.assertEqual(fold_unsupported_chars("naïve"), "naive")


if __name__ == "__main__":
    unittest.main()
