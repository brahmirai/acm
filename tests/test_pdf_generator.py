"""
test_pdf_generator.py - End-to-end tests for PDF generation, parsing, and canary fingerprint recovery.

Verifies:
1. Generate a PDF and verify the file exists on disk.
2. Verify the generated file is a valid PDF structure.
3. Extract the PDF text using document_parser.py.
4. Verify visible content exists in the extracted text.
5. Decode the fingerprint from extracted PDF text (NEET-DEMO-042).
6. Verify decode_fingerprint(extracted_text) == "NEET-DEMO-042".
7. Verify visible text remains intact after remove_fingerprint(extracted_text).
8. Generate another PDF for NEET-DEMO-043 and verify its decoded fingerprint differs.
9. Test TXT extraction preserving Unicode steganography.
10. Test unsupported/missing file handling with clear exceptions.
"""

from pathlib import Path
import pytest
import fitz

import document_parser
import fingerprint
from models import Document, Recipient
import pdf_generator


@pytest.fixture
def demo_recipient() -> Recipient:
    """Standard demonstration recipient as specified in project requirements."""
    return Recipient(
        recipient_uid="NEET-DEMO-042",
        name="Demo Candidate",
        center="Block B",
    )


@pytest.fixture
def demo_document() -> Document:
    """Standard fictional NEET mock examination document."""
    return pdf_generator.create_demo_neet_document()


# Test 1: Generate a PDF and verify the file exists
def test_1_generate_pdf_file_exists(tmp_path: Path, demo_document: Document, demo_recipient: Recipient):
    """Verify that generate_canary_pdf writes a real PDF file to disk."""
    out_pdf = tmp_path / "test_demo_exam.pdf"
    assert not out_pdf.exists()

    result_path = pdf_generator.generate_personalized_pdf(
        document=demo_document,
        recipient=demo_recipient,
        output_path=out_pdf,
    )

    assert result_path.exists()
    assert result_path.is_file()
    assert result_path.stat().st_size > 0


# Test 2: Verify the generated file is a valid PDF
def test_2_verify_valid_pdf(tmp_path: Path, demo_document: Document, demo_recipient: Recipient):
    """Verify generated file is recognized as a valid PDF with header and page objects."""
    out_pdf = tmp_path / "valid_check.pdf"
    pdf_generator.generate_personalized_pdf(
        document=demo_document,
        recipient=demo_recipient,
        output_path=out_pdf,
    )

    # Check magic bytes
    with open(out_pdf, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-"

    # Validate with PyMuPDF
    doc = fitz.open(str(out_pdf))
    try:
        assert doc.page_count >= 1
        assert not doc.is_encrypted
    finally:
        doc.close()


# Test 3: Extract the PDF text using document_parser.py
def test_3_extract_pdf_text(tmp_path: Path, demo_document: Document, demo_recipient: Recipient):
    """Verify document_parser extracts non-empty text from the generated PDF."""
    out_pdf = tmp_path / "extract_check.pdf"
    pdf_generator.generate_personalized_pdf(
        document=demo_document,
        recipient=demo_recipient,
        output_path=out_pdf,
    )

    extracted_text = document_parser.extract_text_from_pdf(out_pdf)
    assert isinstance(extracted_text, str)
    assert len(extracted_text) > 0


# Test 4: Verify visible content exists
def test_4_verify_visible_content_exists(tmp_path: Path, demo_document: Document, demo_recipient: Recipient):
    """Verify expected visible document sections, instructions, and questions are in extracted text."""
    out_pdf = tmp_path / "visible_check.pdf"
    pdf_generator.generate_personalized_pdf(
        document=demo_document,
        recipient=demo_recipient,
        output_path=out_pdf,
    )

    extracted = document_parser.extract_text_from_pdf(out_pdf)

    assert "NEET Mock Examination" in extracted
    assert "PHYSICAL SCIENCES" in extracted
    assert "Demo Candidate" in extracted
    assert "Block B" in extracted
    assert "CANDIDATE INSTRUCTIONS" in extracted


# Test 5 & 6: Decode the fingerprint from extracted PDF text (Critical Round Trip)
def test_5_and_6_critical_round_trip_fingerprint_recovery(
    tmp_path: Path, demo_document: Document, demo_recipient: Recipient
):
    """CRITICAL TEST: Full end-to-end round trip verifying exact recovery of NEET-DEMO-042."""
    out_pdf = tmp_path / "canary_neet_042.pdf"

    # 1. Generate Canary PDF
    pdf_path = pdf_generator.generate_personalized_pdf(
        document=demo_document,
        recipient=demo_recipient,
        output_path=out_pdf,
    )

    # 2. Extract with PyMuPDF
    extracted_text = document_parser.extract_text_from_pdf(pdf_path)

    # 3. Decode Zero-Width Fingerprint
    recovered_uid = fingerprint.decode_fingerprint(extracted_text)

    # 4. Assert exact match with demo recipient UID
    assert recovered_uid is not None
    assert recovered_uid == "NEET-DEMO-042"


# Test 7: Verify visible text remains intact after remove_fingerprint
def test_7_visible_text_preservation_after_sanitization(
    tmp_path: Path, demo_document: Document, demo_recipient: Recipient
):
    """Verify visible text remains intact and pristine when zero-width characters are purged."""
    out_pdf = tmp_path / "sanitize_check.pdf"
    pdf_generator.generate_personalized_pdf(
        document=demo_document,
        recipient=demo_recipient,
        output_path=out_pdf,
    )

    extracted_text = document_parser.extract_text_from_pdf(out_pdf)
    cleaned_text = fingerprint.remove_fingerprint(extracted_text)

    # Fingerprint must be gone
    assert fingerprint.decode_fingerprint(cleaned_text) is None

    # Visible text must still be present
    assert "NEET Mock Examination" in cleaned_text
    assert "PHYSICAL SCIENCES" in cleaned_text
    assert "CANDIDATE INSTRUCTIONS" in cleaned_text


# Test 8: Generate another PDF for NEET-DEMO-043 and verify distinct fingerprints
def test_8_different_recipient_produces_distinct_fingerprint(
    tmp_path: Path, demo_document: Document
):
    """Verify distinct recipient UIDs are faithfully distinguished from extracted PDFs."""
    rec_42 = Recipient(recipient_uid="NEET-DEMO-042", name="Candidate 42", center="Center A")
    rec_43 = Recipient(recipient_uid="NEET-DEMO-043", name="Candidate 43", center="Center B")

    pdf_42 = tmp_path / "exam_42.pdf"
    pdf_43 = tmp_path / "exam_43.pdf"

    pdf_generator.generate_personalized_pdf(demo_document, rec_42, pdf_42)
    pdf_generator.generate_personalized_pdf(demo_document, rec_43, pdf_43)

    ext_42 = document_parser.extract_text_from_pdf(pdf_42)
    ext_43 = document_parser.extract_text_from_pdf(pdf_43)

    dec_42 = fingerprint.decode_fingerprint(ext_42)
    dec_43 = fingerprint.decode_fingerprint(ext_43)

    assert dec_42 == "NEET-DEMO-042"
    assert dec_43 == "NEET-DEMO-043"
    assert dec_42 != dec_43


# Test 9: Test TXT extraction
def test_9_txt_extraction_and_dispatcher(tmp_path: Path):
    """Verify TXT file extraction preserves zero-width fingerprints and dispatcher selects parser."""
    raw_text = "CONFIDENTIAL INTERNAL BRIEFING\n\nMission details: Operation Falcon."
    fp = "AGENT-TX-77"
    encoded = fingerprint.encode_text(raw_text, fp)

    txt_file = tmp_path / "briefing.txt"
    txt_file.write_text(encoded, encoding="utf-8")

    # Direct TXT extraction
    extracted_txt = document_parser.extract_text_from_txt(txt_file)
    assert extracted_txt == encoded
    assert fingerprint.decode_fingerprint(extracted_txt) == fp

    # Dispatcher extraction
    dispatched_txt = document_parser.extract_document_text(txt_file)
    assert dispatched_txt == encoded
    assert fingerprint.decode_fingerprint(dispatched_txt) == fp


# Test 10: Test unsupported and missing file handling
def test_10_missing_and_unsupported_file_handling(tmp_path: Path):
    """Verify clear exceptions are raised for missing files or unsupported extensions."""
    missing_file = tmp_path / "non_existent.pdf"

    # Missing PDF
    with pytest.raises(FileNotFoundError):
        document_parser.extract_text_from_pdf(missing_file)

    # Missing TXT
    with pytest.raises(FileNotFoundError):
        document_parser.extract_text_from_txt(tmp_path / "missing.txt")

    # Missing in dispatcher
    with pytest.raises(FileNotFoundError):
        document_parser.extract_document_text(tmp_path / "missing.doc")

    # Unsupported format
    unsupported_file = tmp_path / "image.png"
    unsupported_file.write_bytes(b"\x89PNG\r\n\x1a\n")

    with pytest.raises(ValueError, match="Unsupported document format"):
        document_parser.extract_document_text(unsupported_file)
