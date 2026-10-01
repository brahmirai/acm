"""
test_fingerprint.py - Comprehensive test suite for zero-width fingerprint engine.

Verifies:
1. Basic encode/decode ("Hello CanaryDocs", "NEET-DEMO-042")
2. Visible text preservation (remove_fingerprint(encode_text(text, fp)) == text)
3. No fingerprint returns None
4. Empty text handled safely
5. Empty fingerprint handled safely
6. Unicode visible text ("Confidential परीक्षा document")
7. Special characters in fingerprint ("RECIPIENT-ABC_123", punctuation, symbols)
8. Corrupted fingerprint returns None rather than crash
9. Truncated fingerprint returns None
10. Multiple encoded fingerprints behavior (returns first valid; remove cleans all)
11. Different fingerprints produce different encoded results
12. remove_fingerprint removes fingerprint data completely
13. Boundary conditions (maximum length rejection, type errors)
"""

import pytest

import fingerprint
from fingerprint import (
    END_MARKER,
    MAX_FINGERPRINT_BYTES,
    START_MARKER,
    ZERO_WIDTH_CHARS,
    ZWJ,
    ZWNBSP,
    ZWNJ,
    ZWSP,
    decode_fingerprint,
    encode_text,
    remove_fingerprint,
)


# Constants & Architecture Verification
def test_zero_width_constants():
    """Verify zero-width character set and markers are properly defined."""
    assert ZWSP == "\u200b"
    assert ZWNJ == "\u200c"
    assert ZWJ == "\u200d"
    assert ZWNBSP == "\ufeff"
    assert len(ZERO_WIDTH_CHARS) == 4
    assert all(c in ZERO_WIDTH_CHARS for c in (ZWSP, ZWNJ, ZWJ, ZWNBSP))


# 1. Basic Encode / Decode
def test_basic_encode_decode():
    """Verify fundamental encode and decode roundtrip."""
    text = "Hello CanaryDocs"
    fp = "NEET-DEMO-042"

    encoded = encode_text(text, fp)
    assert encoded != text
    assert len(encoded) > len(text)

    decoded = decode_fingerprint(encoded)
    assert decoded == fp


# 2. Visible Text Preservation
def test_visible_text_preservation():
    """Verify remove_fingerprint perfectly restores the canonical text."""
    text = "CANARYDOCS confidential examination document."
    fp = "NEET-DEMO-042"

    encoded = encode_text(text, fp)
    restored = remove_fingerprint(encoded)

    assert restored == text
    assert decode_fingerprint(restored) is None


# 3. No Fingerprint
def test_no_fingerprint():
    """Verify text without an embedded fingerprint decodes to None."""
    assert decode_fingerprint("Plain unwatermarked document text.") is None
    assert decode_fingerprint("Another normal sentence without invisible characters.") is None


# 4. Empty Text
def test_empty_text_handled_safely():
    """Verify encoding onto an empty text string works and can be decoded."""
    fp = "NEET-DEMO-EMPTY-TEXT"
    encoded = encode_text("", fp)

    assert len(encoded) > 0
    assert decode_fingerprint(encoded) == fp
    assert remove_fingerprint(encoded) == ""


# 5. Empty Fingerprint
def test_empty_fingerprint_handled_safely():
    """Verify passing an empty fingerprint returns original text unmodified."""
    text = "Sample confidential memo."
    result = encode_text(text, "")

    assert result == text
    assert decode_fingerprint(result) is None


# 6. Unicode Visible Text
def test_unicode_visible_text():
    """Verify visible non-ASCII Unicode characters (e.g. Hindi, accents) are preserved."""
    text = "Confidential परीक्षा document avec des caractères spéciaux."
    fp = "EXAM-2026-XYZ"

    encoded = encode_text(text, fp)
    decoded = decode_fingerprint(encoded)
    restored = remove_fingerprint(encoded)

    assert decoded == fp
    assert restored == text
    assert "परीक्षा" in restored


# 7. Special Characters in Fingerprint
def test_special_characters_in_fingerprint():
    """Verify fingerprints containing dashes, underscores, symbols, and Unicode survive."""
    test_fps = [
        "RECIPIENT-ABC_123",
        "CLEARANCE#LEVEL:TOP_SECRET//DEPT=09",
        "AGENT@CENTRAL.ORG[ALPHA-99]",
        "गोपनीय-आईडी-२०२६",  # Unicode in fingerprint payload
    ]

    base_text = "Operational directives for field units."
    for fp in test_fps:
        encoded = encode_text(base_text, fp)
        assert decode_fingerprint(encoded) == fp
        assert remove_fingerprint(encoded) == base_text


# 8. Corrupted Fingerprint
def test_corrupted_fingerprint_returns_none():
    """Verify bit corruption or checksum mismatch safely returns None without raising."""
    text = "Top secret strategy report."
    fp = "SEC-CORRUPT-TEST"
    encoded = encode_text(text, fp)

    # Locate the bit body between markers
    start = encoded.find(START_MARKER) + len(START_MARKER)
    end = encoded.find(END_MARKER)
    bits = list(encoded[start:end])

    # Flip bits in the payload
    if len(bits) > 10:
        bits[10] = ZWNJ if bits[10] == ZWSP else ZWSP
        corrupted = encoded[:start] + "".join(bits) + encoded[end:]
        assert decode_fingerprint(corrupted) is None

    # Replace bits with an invalid zero-width character
    if len(bits) > 5:
        bits[5] = ZWJ  # Invalid bit character (not ZWSP or ZWNJ)
        corrupted_char = encoded[:start] + "".join(bits) + encoded[end:]
        assert decode_fingerprint(corrupted_char) is None


# 9. Truncated Fingerprint
def test_truncated_fingerprint_returns_none():
    """Verify truncated or cut-off encoded text returns None without crashing."""
    text = "Classified intelligence brief."
    fp = "NEET-TRUNCATE-001"
    encoded = encode_text(text, fp)

    # Truncate end marker away
    cut_before_end = encoded[: encoded.find(END_MARKER)]
    assert decode_fingerprint(cut_before_end) is None

    # Truncate halfway through payload
    cut_halfway = encoded[: len(encoded) // 2]
    assert decode_fingerprint(cut_halfway) is None

    # Remove just one character from bits
    start = encoded.find(START_MARKER) + len(START_MARKER)
    cut_single_bit = encoded[:start] + encoded[start + 1 :]
    assert decode_fingerprint(cut_single_bit) is None


# 10. Multiple Encoded Fingerprints
def test_multiple_fingerprints():
    """Verify documented behavior: decode returns first valid, remove strips all."""
    base_text = "Multi-party intelligence dissemination protocol."
    fp1 = "RECIPIENT-ALPHA-1"
    fp2 = "RECIPIENT-BETA-2"

    # Encode first fingerprint
    doc_with_fp1 = encode_text(base_text, fp1)

    # Append or encode a second fingerprint at a later position
    second_payload = fingerprint._encode_payload(fp2)
    doc_with_two_fps = doc_with_fp1 + " Additional remarks " + second_payload

    # decode_fingerprint returns the FIRST valid fingerprint encountered
    first_detected = decode_fingerprint(doc_with_two_fps)
    assert first_detected == fp1

    # remove_fingerprint strips all fingerprint blocks and zero-width characters
    fully_cleaned = remove_fingerprint(doc_with_two_fps)
    assert fp1 not in fully_cleaned
    assert fp2 not in fully_cleaned
    assert decode_fingerprint(fully_cleaned) is None
    assert fully_cleaned == base_text + " Additional remarks "


# 11. Different Fingerprints Produce Different Encoded Results
def test_different_fingerprints_differ():
    """Verify distinct fingerprints produce distinct encoded byte/character streams."""
    text = "Standard classified report."
    encoded_1 = encode_text(text, "RECIPIENT-001")
    encoded_2 = encode_text(text, "RECIPIENT-002")

    assert encoded_1 != encoded_2
    assert decode_fingerprint(encoded_1) == "RECIPIENT-001"
    assert decode_fingerprint(encoded_2) == "RECIPIENT-002"


# 12. remove_fingerprint Removes Fingerprint Data Completely
def test_remove_fingerprint_completely_cleans():
    """Verify remove_fingerprint eliminates all traces of zero-width steganography."""
    text = "Critical mission parameters."
    fp = "PURGE-TEST-001"
    encoded = encode_text(text, fp)

    cleaned = remove_fingerprint(encoded)
    assert cleaned == text

    # Confirm no zero-width character exists in cleaned text
    for char in ZERO_WIDTH_CHARS:
        assert char not in cleaned


# 13. Validation & Edge Cases
def test_validation_and_size_limits():
    """Verify type checking and payload size limit enforcement."""
    # Type errors
    with pytest.raises(TypeError):
        encode_text(12345, "VALID-FP")  # type: ignore

    with pytest.raises(TypeError):
        encode_text("Valid text", 99999)  # type: ignore

    # None inputs to decode/remove
    assert decode_fingerprint(None) is None  # type: ignore
    assert remove_fingerprint(None) == ""  # type: ignore

    # Excessively long fingerprint payload
    oversized_fp = "A" * (MAX_FINGERPRINT_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed length"):
        encode_text("Valid text", oversized_fp)


# 14. Documented Limitation Check
def test_limitation_documented():
    """Verify architectural limitation regarding OCR/screenshots is documented."""
    module_doc = fingerprint.__doc__ or ""
    assert "OCR" in module_doc
    assert "screenshots" in module_doc.lower()
    assert "rasterization" in module_doc.lower()
