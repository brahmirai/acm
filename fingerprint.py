"""
fingerprint.py - Zero-width Unicode fingerprint encoding, decoding, and sanitization.

CANARYDOCS Steganography Engine:
Embeds invisible, recipient-specific fingerprints into confidential text documents
using a compact, deterministic alphabet of zero-width Unicode characters.

ENCODING SCHEME (Version 1):
----------------------------
1. Frame Delimiters:
   - START_MARKER: '\u200d\ufeff\u200d' (ZWJ + ZWNBSP + ZWJ)
   - END_MARKER:   '\ufeff\u200d\ufeff' (ZWNBSP + ZWJ + ZWNBSP)
2. Bit Alphabet:
   - '0' -> ZWSP  ('\u200b', Zero-Width Space)
   - '1' -> ZWNJ  ('\u200c', Zero-Width Non-Joiner)
3. Binary Frame Layout:
   - Version: 8 bits (uint8, default 0x01)
   - Payload Length: 16 bits (uint16 big-endian, byte length of UTF-8 fingerprint)
   - Fingerprint Data: N * 8 bits (UTF-8 encoded string)
   - Checksum: 8 bits (XOR reduction across version + length + data bytes)
4. Placement:
   - Inserted deterministically near the beginning of the document text immediately
     after the first whitespace character (or after the initial character if no whitespace).
   - This preserves initial layout/kerning while ensuring the payload survives
     PDF text layer extraction and digital copy-paste operations.

CRITICAL ARCHITECTURAL LIMITATION:
----------------------------------
Zero-width Unicode fingerprints depend strictly on underlying Unicode codepoints surviving.
They survive:
  - Direct digital copy/paste
  - PDF text-layer extraction (PyMuPDF)
  - Plaintext (.txt) conversion
They DO NOT survive and are NOT expected to survive:
  - Screenshots
  - Rasterization
  - Optical Character Recognition (OCR)
  - Image conversion / scanning
Because zero-width codepoints have no visual glyph or pixel representation, any raster
rendering permanently destroys the fingerprint.
"""

from __future__ import annotations

import re
from typing import Optional

# Zero-Width Unicode Codepoints used for steganographic binary encoding
ZWSP = "\u200b"    # Zero-Width Space (Binary 0)
ZWNJ = "\u200c"    # Zero-Width Non-Joiner (Binary 1)
ZWJ = "\u200d"     # Zero-Width Joiner (Framing boundary)
ZWNBSP = "\ufeff"  # Zero-Width No-Break Space / BOM (Framing boundary)

ZERO_WIDTH_CHARS = (ZWSP, ZWNJ, ZWJ, ZWNBSP)

# Frame Markers and Constraints
START_MARKER = f"{ZWJ}{ZWNBSP}{ZWJ}"
END_MARKER = f"{ZWNBSP}{ZWJ}{ZWNBSP}"
CURRENT_VERSION = 1
MAX_FINGERPRINT_BYTES = 256


def _find_insertion_point(text: str) -> int:
    """Determine a predictable, safe insertion point for the fingerprint payload.

    Places the fingerprint near the beginning of the text immediately after the
    first whitespace character. If no whitespace exists, inserts after the first character.

    Args:
        text: Plain visible document text.

    Returns:
        Index where the zero-width payload should be inserted.
    """
    if not text:
        return 0

    first_chunk = text[:50]
    for i, char in enumerate(first_chunk):
        if char.isspace():
            return i + 1

    return min(len(text), 1)


def _encode_payload(fingerprint: str) -> str:
    """Pack and translate a fingerprint string into a zero-width Unicode frame.

    Frame format:
        [START_MARKER]
        [Version: 1 byte]
        [Length: 2 bytes]
        [Data: N bytes]
        [Checksum: 1 byte]
        [END_MARKER]

    Args:
        fingerprint: String identifier to encode.

    Returns:
        String of zero-width Unicode characters.

    Raises:
        ValueError: If fingerprint exceeds maximum size or is invalid.
    """
    raw_bytes = fingerprint.encode("utf-8")
    if len(raw_bytes) > MAX_FINGERPRINT_BYTES:
        raise ValueError(
            f"Fingerprint exceeds maximum allowed length of {MAX_FINGERPRINT_BYTES} bytes."
        )

    version_byte = bytes([CURRENT_VERSION])
    len_bytes = len(raw_bytes).to_bytes(2, byteorder="big")
    payload_body = version_byte + len_bytes + raw_bytes

    # XOR checksum across version, length, and payload data
    checksum = 0
    for b in payload_body:
        checksum ^= b
    full_frame = payload_body + bytes([checksum])

    # Convert bytes to zero-width bit string
    bit_chars: list[str] = []
    for b in full_frame:
        for bit_idx in range(7, -1, -1):
            bit = (b >> bit_idx) & 1
            bit_chars.append(ZWNJ if bit == 1 else ZWSP)

    return f"{START_MARKER}{''.join(bit_chars)}{END_MARKER}"


def encode_text(text: str, fingerprint: str) -> str:
    """Encode an invisible recipient-specific fingerprint into text.

    Inserts an invisible zero-width Unicode sequence containing the framed,
    checksummed fingerprint payload at a deterministic location near the start
    of the text.

    Args:
        text: Original plain text to be watermarked.
        fingerprint: Unique identifier or token associated with recipient.

    Returns:
        The text containing embedded zero-width Unicode fingerprint.

    Raises:
        TypeError: If fingerprint or text is not a string.
        ValueError: If fingerprint payload exceeds maximum size limit.
    """
    if not isinstance(text, str):
        raise TypeError("Text must be a string.")
    if not isinstance(fingerprint, str):
        raise TypeError("Fingerprint must be a string.")

    if not fingerprint:
        return text

    payload = _encode_payload(fingerprint)
    if not text:
        return payload

    insert_idx = _find_insertion_point(text)
    return text[:insert_idx] + payload + text[insert_idx:]


def decode_fingerprint(text: str) -> Optional[str]:
    """Scan text and decode any embedded zero-width Unicode fingerprint.

    Scans for CanaryDocs framing markers, validates frame version, length,
    and checksum, and extracts the original fingerprint string.

    Behavior:
    - If multiple fingerprints exist, returns the first valid CanaryDocs fingerprint.
    - If the fingerprint is absent, malformed, or corrupted, safely returns None
      without throwing exceptions.

    Args:
        text: Text extracted from a leaked or submitted document.

    Returns:
        Decoded fingerprint string if detected and valid; None otherwise.
    """
    if not text or not isinstance(text, str):
        return None

    start_pos = 0
    while True:
        start_idx = text.find(START_MARKER, start_pos)
        if start_idx == -1:
            break

        start_pos = start_idx + len(START_MARKER)
        end_idx = text.find(END_MARKER, start_pos)
        if end_idx == -1:
            continue

        bit_chars = text[start_pos:end_idx]

        # Bit sequence must be non-empty and byte-aligned (multiple of 8)
        if not bit_chars or len(bit_chars) % 8 != 0:
            continue

        # All characters must be zero-width data bits
        if any(c not in (ZWSP, ZWNJ) for c in bit_chars):
            continue

        try:
            byte_values: list[int] = []
            for i in range(0, len(bit_chars), 8):
                byte_bits = bit_chars[i : i + 8]
                byte_val = 0
                for char in byte_bits:
                    byte_val = (byte_val << 1) | (1 if char == ZWNJ else 0)
                byte_values.append(byte_val)

            raw_bytes = bytes(byte_values)

            # Frame must contain at minimum: version (1) + length (2) + data (0) + checksum (1) = 4 bytes
            if len(raw_bytes) < 4:
                continue

            version = raw_bytes[0]
            if version != CURRENT_VERSION:
                continue

            data_len = int.from_bytes(raw_bytes[1:3], byteorder="big")
            if data_len > MAX_FINGERPRINT_BYTES:
                continue

            expected_total_len = 1 + 2 + data_len + 1
            if len(raw_bytes) != expected_total_len:
                continue

            payload_body = raw_bytes[: 1 + 2 + data_len]
            checksum_byte = raw_bytes[1 + 2 + data_len]

            # Verify XOR checksum
            calc_checksum = 0
            for b in payload_body:
                calc_checksum ^= b

            if calc_checksum != checksum_byte:
                continue

            fingerprint_bytes = raw_bytes[3 : 3 + data_len]
            return fingerprint_bytes.decode("utf-8")

        except Exception:
            # Safely continue to search for subsequent valid markers
            continue

    return None


def remove_fingerprint(text: str) -> str:
    """Strip all zero-width steganographic characters from the text.

    Removes all CanaryDocs fingerprint blocks and any zero-width Unicode
    characters, completely restoring the original pristine visible text.

    Args:
        text: Fingerprinted or suspicious text.

    Returns:
        Clean plain text with zero-width Unicode codepoints removed.
    """
    if not text or not isinstance(text, str):
        return text if text is not None else ""

    # 1. Strip framed CanaryDocs fingerprint blocks
    pattern = re.compile(
        rf"{re.escape(START_MARKER)}[\u200b\u200c]*?{re.escape(END_MARKER)}"
    )
    cleaned = pattern.sub("", text)

    # 2. Strip any remaining zero-width steganographic characters
    return "".join(c for c in cleaned if c not in ZERO_WIDTH_CHARS)
