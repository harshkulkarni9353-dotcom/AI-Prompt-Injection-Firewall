import base64
import re
import unicodedata


# ============================================================
# SUSPICIOUS TERMS AFTER DECODING
# ============================================================

SUSPICIOUS_DECODED_TERMS = [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "disregard all previous",
    "forget previous",
    "forget all previous",
    "system prompt",
    "hidden instructions",
    "reveal instructions",
    "reveal your prompt",
    "show your system prompt",
    "bypass",
    "jailbreak",
    "override instructions",
    "override your instructions",
    "disable safety",
    "remove restrictions",
]


# ============================================================
# HELPER: CHECK SUSPICIOUS CONTENT
# ============================================================

def contains_suspicious_content(text: str):

    text_lower = text.lower()

    return any(
        term in text_lower
        for term in SUSPICIOUS_DECODED_TERMS
    )


# ============================================================
# OBFUSCATION DETECTION
# ============================================================

def detect_obfuscation(prompt: str):

    indicators = []
    decoded_content = []

    if not prompt:

        return {
            "is_obfuscated": False,
            "indicators": [],
            "decoded_content": []
        }


    # ========================================================
    # 1. BASE64 DETECTION
    # ========================================================

    # Look for reasonably long Base64-looking tokens.
    base64_candidates = re.findall(
        r"(?<![A-Za-z0-9+/=])"
        r"[A-Za-z0-9+/]{12,}={0,2}"
        r"(?![A-Za-z0-9+/=])",
        prompt
    )

    for candidate in base64_candidates:

        # Base64 length should be compatible with groups of 4.
        if len(candidate) % 4 != 0:
            continue

        try:

            decoded_bytes = base64.b64decode(
                candidate,
                validate=True
            )

            decoded = decoded_bytes.decode(
                "utf-8"
            )

            decoded_clean = decoded.strip()

            if not decoded_clean:
                continue

            # Require readable text.
            printable_ratio = (
                sum(
                    char.isprintable()
                    for char in decoded_clean
                )
                / len(decoded_clean)
            )

            if printable_ratio < 0.85:
                continue

            # IMPORTANT:
            # Only flag Base64 if its decoded content
            # contains suspicious security instructions.

            if contains_suspicious_content(
                decoded_clean
            ):

                indicators.append(
                    "BASE64_SUSPICIOUS_CONTENT"
                )

                decoded_content.append({
                    "encoding": "base64",
                    "original": candidate,
                    "decoded": decoded_clean
                })

        except Exception:
            continue


    # ========================================================
    # 2. HEX ENCODING
    # ========================================================

    hex_candidates = re.findall(
        r"\b(?:[0-9a-fA-F]{2}){4,}\b",
        prompt
    )

    for candidate in hex_candidates:

        try:

            decoded_bytes = bytes.fromhex(
                candidate
            )

            decoded = decoded_bytes.decode(
                "utf-8"
            )

            decoded_clean = decoded.strip()

            if not decoded_clean:
                continue

            printable_ratio = (
                sum(
                    char.isprintable()
                    for char in decoded_clean
                )
                / len(decoded_clean)
            )

            if printable_ratio < 0.85:
                continue

            # Only flag when decoded content is suspicious.
            if contains_suspicious_content(
                decoded_clean
            ):

                indicators.append(
                    "HEX_SUSPICIOUS_CONTENT"
                )

                decoded_content.append({
                    "encoding": "hex",
                    "original": candidate,
                    "decoded": decoded_clean
                })

        except Exception:
            continue


    # ========================================================
    # 3. ZERO-WIDTH CHARACTERS
    # ========================================================

    zero_width_chars = [
        "\u200b",
        "\u200c",
        "\u200d",
        "\u2060",
        "\ufeff"
    ]

    zero_width_count = sum(
        prompt.count(char)
        for char in zero_width_chars
    )

    if zero_width_count > 0:

        indicators.append(
            "ZERO_WIDTH_CHARACTERS"
        )


    # ========================================================
    # 4. UNICODE / HOMOGLYPH DETECTION
    # ========================================================

    suspicious_unicode = []

    for char in prompt:

        if ord(char) <= 127:
            continue

        name = unicodedata.name(
            char,
            ""
        ).lower()

        if any(
            keyword in name
            for keyword in [
                "cyrillic",
                "greek",
                "fullwidth",
                "modifier"
            ]
        ):

            suspicious_unicode.append(char)

    if suspicious_unicode:

        indicators.append(
            "UNICODE_HOMOGLYPH_INDICATOR"
        )


    # ========================================================
    # 5. ESCAPED CHARACTER SEQUENCES
    # ========================================================

    escape_sequences = re.findall(
        r"(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})",
        prompt
    )

    if len(escape_sequences) >= 2:

        indicators.append(
            "ESCAPED_CHARACTER_SEQUENCE"
        )


    # ========================================================
    # 6. CHARACTER FRAGMENTATION
    # ========================================================

    fragmented_patterns = [

        r"i\s+g\s+n\s+o\s+r\s+e",

        r"b\s+y\s+p\s+a\s+s\s+s",

        r"s\s+y\s+s\s+t\s+e\s+m",

        r"p\s+r\s+o\s+m\s+p\s+t",

        r"j\s+a\s+i\s+l\s+b\s+r\s+e\s+a\s+k"

    ]

    for pattern in fragmented_patterns:

        if re.search(
            pattern,
            prompt,
            re.IGNORECASE
        ):

            indicators.append(
                "CHARACTER_FRAGMENTATION"
            )

            break


    # ========================================================
    # 7. HIGH SPECIAL CHARACTER RATIO
    # ========================================================

    special_count = len(
        re.findall(
            r"[^a-zA-Z0-9\s]",
            prompt
        )
    )

    if (
        len(prompt) > 30
        and special_count / len(prompt) > 0.35
    ):

        indicators.append(
            "HIGH_SPECIAL_CHARACTER_RATIO"
        )


    # ========================================================
    # REMOVE DUPLICATES
    # ========================================================

    indicators = list(
        dict.fromkeys(indicators)
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "is_obfuscated":
            len(indicators) > 0,

        "indicators":
            indicators,

        "decoded_content":
            decoded_content
    }