"""
Prompt Guard - Text normalization.

Handles homoglyph replacement, delimiter stripping, character spacing collapse,
quoted-fragment reassembly, comment-insertion stripping, and whitespace normalization.
"""

import re

# Unicode homoglyphs (expanded)
HOMOGLYPHS = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "А": "A",
    "В": "B",
    "С": "C",
    "Е": "E",
    "Н": "H",
    "К": "K",
    "М": "M",
    "О": "O",
    "Р": "P",
    "Т": "T",
    "Х": "X",
    "і": "i",
    "ї": "i",
    # Greek
    "α": "a",
    "β": "b",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "ν": "v",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # Mathematical/special
    "𝐚": "a",
    "𝐛": "b",
    "𝐜": "c",
    "𝐝": "d",
    "𝐞": "e",
    "𝐟": "f",
    "𝐠": "g",
    "ａ": "a",
    "ｂ": "b",
    "ｃ": "c",
    "ｄ": "d",
    "ｅ": "e",  # Fullwidth
    "ⅰ": "i",
    "ⅱ": "ii",
    "ⅲ": "iii",
    "ⅳ": "iv",
    "ⅴ": "v",  # Roman numerals
    # IPA
    "ɑ": "a",
    "ɡ": "g",
    "ɩ": "i",
    "ʀ": "r",
    "ʏ": "y",
    # Other confusables
    "ℓ": "l",
    "№": "no",
    "℮": "e",
    "ⅿ": "m",
    "\u200b": "",  # Zero-width space
    "\u200c": "",  # Zero-width non-joiner
    "\u200d": "",  # Zero-width joiner
    "\ufeff": "",  # BOM
}


def normalize(text: str) -> tuple:
    """Normalize text: homoglyphs, delimiters, spacing, quotes, comments, tabs.
    Returns (normalized_text, has_homoglyphs, was_defragmented).

    v2.8.2 additions (security report response):
      - Quoted-fragment reassembly: "ig" "nore" -> ignore
      - Comment-insertion stripping: 업/**/로드 -> 업로드
      - Tab/exotic whitespace normalization
      - Backtick/bracket fragment reassembly
      - Code-style concatenation reassembly
    """
    normalized = text
    has_homoglyphs = False
    was_defragmented = False

    # -- 0. Zero-width & invisible character stripping ----------------
    #    Must happen first so later steps see clean text.
    invisible_strip = re.compile(
        r"[\u200b\u200c\u200d\u200e\u200f"
        r"\u2028\u2029"              # line/paragraph separators
        r"\u2060\u2061\u2062\u2063\u2064"  # invisible operators
        r"\u00ad"                    # soft hyphen
        r"\ufeff"                    # BOM
        r"\U000E0001-\U000E007F"     # Unicode tags
        r"]"
    )
    stripped = invisible_strip.sub("", normalized)
    if len(stripped) != len(normalized):
        was_defragmented = True
        normalized = stripped

    # -- 1. Homoglyph normalization -----------------------------------
    for homoglyph, replacement in HOMOGLYPHS.items():
        if homoglyph in normalized:
            has_homoglyphs = True
            normalized = normalized.replace(homoglyph, replacement)

    # -- 2. (removed) Comment-insertion stripping removed in v4.0.0
    #    Was stripping /**/ and // between chars, but caused false positives
    #    on URLs (http://), JS code, etc. Not a realistic LLM attack vector.

    # -- 3. Tab / exotic whitespace normalization ---------------------
    #    Replace tabs, NBSP, ideographic space, etc. with regular space
    prev = normalized
    normalized = re.sub(r"[\t\u00a0\u3000\u2000-\u200a\u205f]", " ", normalized)
    if normalized != prev:
        was_defragmented = True

    # -- Steps 4-8 removed in v4.0.0 ---------------------------------
    #    Quoted-fragment, bracket, code-join, delimiter, spacing reassembly
    #    all removed. Modern LLMs don't interpret these fragmented forms
    #    as executable instructions. These rules only caused false positives
    #    on normal JSON, code, and documentation.

    # -- 9. Collapse multiple spaces ----------------------------------
    normalized = re.sub(r"  +", " ", normalized).strip()

    return normalized, has_homoglyphs, was_defragmented
