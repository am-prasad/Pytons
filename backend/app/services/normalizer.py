"""
AgentShield Text Normalizer
Performs deterministic adversarial text de-obfuscation:
- NFKC unicode normalization
- Zero-width character stripping
- Homoglyph normalization (Cyrillic, Greek lookalikes)
- Base64 block detection and payload decoding
- URL percent-decoding
- HTML comment / tag unmasking
Records all applied transformations as flags for audit and risk scoring.
"""
from __future__ import annotations

import base64
import html
import re
import unicodedata
import urllib.parse
from typing import List, Tuple

# Common Cyrillic & Greek homoglyphs used to evade ASCII regex
HOMOGLYPH_MAP = {
    # Cyrillic lowercase
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    # Cyrillic uppercase
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O',
    'Р': 'P', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    # Greek
    'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'χ': 'x',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P',
    'Τ': 'T', 'Χ': 'X',
}

ZERO_WIDTH_CHARS = re.compile(r'[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2060\u00AD\u202A\u202B\u202C\u202D\u202E]')
BASE64_PATTERN = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b')
HTML_COMMENT_PATTERN = re.compile(r'<!--(.*?)-->', re.DOTALL)


def normalize_text(raw_text: str) -> Tuple[str, List[str]]:
    """
    Applies comprehensive security normalization to raw text.
    Returns: (normalized_text, flags)
    """
    if not raw_text:
        return "", []

    flags: List[str] = []
    text = raw_text

    # 1. NFKC Unicode Normalization
    nfkc_text = unicodedata.normalize('NFKC', text)
    if nfkc_text != text:
        flags.append("nfkc_normalized")
        text = nfkc_text

    # 2. Strip Zero-Width & Invisible Characters
    if ZERO_WIDTH_CHARS.search(text):
        flags.append("zero_width_chars_removed")
        text = ZERO_WIDTH_CHARS.sub('', text)

    # 3. Homoglyph Substitution
    replaced_homoglyphs = 0
    chars = []
    for char in text:
        if char in HOMOGLYPH_MAP:
            chars.append(HOMOGLYPH_MAP[char])
            replaced_homoglyphs += 1
        else:
            chars.append(char)
    if replaced_homoglyphs > 0:
        flags.append(f"homoglyphs_replaced({replaced_homoglyphs})")
        text = "".join(chars)

    # 4. URL Percent-Encoding Decoding
    if "%" in text:
        try:
            unquoted = urllib.parse.unquote(text)
            if unquoted != text:
                flags.append("url_encoding_decoded")
                text = unquoted
        except Exception:
            pass

    # 5. HTML Entity & Comment Decoding
    if "<!--" in text:
        comments = HTML_COMMENT_PATTERN.findall(text)
        if comments:
            flags.append("html_comments_extracted")
            comment_text = " ".join(c.strip() for c in comments if c.strip())
            text = HTML_COMMENT_PATTERN.sub(' ', text) + "\n[DECODED_HTML_COMMENT]: " + comment_text

    unescaped = html.unescape(text)
    if unescaped != text:
        flags.append("html_entities_unescaped")
        text = unescaped

    # 6. Base64 Encoded Payload Detection & Appending
    b64_matches = BASE64_PATTERN.findall(text)
    decoded_payloads = []
    for match in b64_matches:
        if len(match) >= 16:
            try:
                decoded_bytes = base64.b64decode(match, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore').strip()
                # Verify it looks like legible text and contains alpha words
                if len(decoded_str) >= 8 and any(c.isalpha() for c in decoded_str):
                    decoded_payloads.append(decoded_str)
            except Exception:
                pass

    if decoded_payloads:
        flags.append(f"base64_payload_decoded({len(decoded_payloads)})")
        text += "\n[DECODED_BASE64_PAYLOAD]: " + " ".join(decoded_payloads)

    return text.strip(), flags
