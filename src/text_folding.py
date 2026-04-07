"""
Fold characters that the MHFrontier game cannot render.

The PC version of MHFrontier ships with custom bitmap fonts that cover
the JIS X 0208 set used by the Japanese release plus a small ASCII
range. They do **not** include the Latin glyphs with diacritics that
European languages need (``é è ê à â ô ù û î ç œ « »`` etc.), nor
several common typographic punctuation marks.

Writing those characters into the binary as their proper Shift-JIS-2004
codepoints round-trips losslessly through the encoder, but renders as
missing-glyph boxes (or wrong glyphs) in-game because the font has no
matching entry. Until the custom font is extended to add the missing
glyphs, the only practical workaround when importing translations for
languages like French is to **fold the unsupported characters down to
their nearest ASCII equivalents** before encoding.

This module provides that folding step. It is **opt-in**: callers must
ask for it explicitly via a flag (e.g. ``--fold-unsupported-chars`` on
the CLI). The default behaviour of FTH is unchanged so that Japanese
imports stay byte-identical to the source.

The mapping is intentionally lossy and irreversible. Translations
should still be authored with proper diacritics in their source CSVs;
the folding only happens on the way to the binary, so the source of
truth keeps full typographic quality and can be re-emitted intact once
the font supports the missing glyphs.
"""
from __future__ import annotations

import unicodedata


# Replacements that NFKD + combining-mark stripping does not handle
# (ligatures, typographic punctuation, French quotation marks…).
# Order matters only for multi-character outputs.
_LIGATURE_AND_PUNCTUATION: tuple[tuple[str, str], ...] = (
    ("œ", "oe"),
    ("Œ", "Oe"),
    ("æ", "ae"),
    ("Æ", "Ae"),
    ("ß", "ss"),
    ("«", '"'),
    ("»", '"'),
    ("\u201c", '"'),  # left double quotation mark
    ("\u201d", '"'),  # right double quotation mark
    ("\u2018", "'"),  # left single quotation mark
    ("\u2019", "'"),  # right single quotation mark / typographic apostrophe
    ("\u2026", "..."),  # horizontal ellipsis
    ("\u2013", "-"),  # en dash
    ("\u2014", "-"),  # em dash
    ("\u2212", "-"),  # minus sign
    ("\u00a0", " "),  # non-breaking space
    ("\u202f", " "),  # narrow no-break space
    ("\u2009", " "),  # thin space
)


# Unicode range that NFKD-folding is safe to apply to. Covers Latin-1
# Supplement, Latin Extended-A and Latin Extended-B — all the European
# Latin diacritics we want to flatten (é è ê ë à â ä ç î ï ô ö ù û ü ÿ
# ñ ą č ě ł ř ś ž …). Crucially, it does **not** include the CJK
# blocks: applying NFKD to a katakana character like ``グ`` (U+30B0)
# decomposes it to ``ク`` + combining dakuten and would silently strip
# the dakuten when combining marks are dropped. The Japanese strings
# in MHF must be left untouched.
_LATIN_FOLD_MIN = 0x0080
_LATIN_FOLD_MAX = 0x024F


def fold_unsupported_chars(text: str) -> str:
    """
    Fold characters not present in the MHFrontier custom font.

    Performs two passes:

    1. Replace ligatures and typographic punctuation that Unicode
       normalisation cannot decompose (``œ``→``oe``, ``«``→``"``,
       ``…``→``...``, etc.).
    2. For each character in the Latin-1/Latin Extended range only,
       apply NFKD normalisation and drop combining marks, collapsing
       accented Latin letters to their base form (``é``→``e``,
       ``ç``→``c``, ``À``→``A``, …).

    Characters outside the Latin range — ASCII, CJK ideographs,
    hiragana, katakana, full-width Japanese punctuation — are returned
    untouched. This is critical: blanket NFKD on katakana would
    decompose dakuten/handakuten characters like ``グ`` into base
    ``ク`` + combining mark and silently corrupt Japanese text.

    :param text: Input string in any Unicode form.
    :return: Folded string suitable for encoding to the binary when the
        in-game font lacks the original glyphs.

    >>> fold_unsupported_chars("Méga potion")
    'Mega potion'
    >>> fold_unsupported_chars("Drogue du démon")
    'Drogue du demon'
    >>> fold_unsupported_chars("cœur")
    'coeur'
    >>> fold_unsupported_chars("« Épée »")
    '" Epee "'
    >>> fold_unsupported_chars("回復薬グレート")
    '回復薬グレート'
    """
    if not text:
        return text
    for src, dst in _LIGATURE_AND_PUNCTUATION:
        if src in text:
            text = text.replace(src, dst)
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if _LATIN_FOLD_MIN <= cp <= _LATIN_FOLD_MAX:
            decomposed = unicodedata.normalize("NFKD", ch)
            out.append(
                "".join(c for c in decomposed if not unicodedata.combining(c))
            )
        else:
            out.append(ch)
    return "".join(out)
