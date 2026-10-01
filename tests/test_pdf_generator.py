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


# Test 11: In-Situ PDF Format Preservation & Watermark Embedding
def test_11_embed_fingerprint_in_pdf_preserves_multipage_and_visual_elements(tmp_path: Path):
    """Verify embed_fingerprint_in_pdf preserves multi-page layouts, graphics, and tables while embedding watermark."""
    import fitz

    # Create a complex multi-page source PDF with vector graphics and layout
    source_pdf_path = tmp_path / "source_exam.pdf"
    doc = fitz.open()

    # Page 1: Physics with vector rectangle & title
    p1 = doc.new_page(width=595, height=842)
    p1.draw_rect(fitz.Rect(50, 50, 545, 120), color=(0.1, 0.2, 0.5), fill=(0.9, 0.95, 1.0))
    p1.insert_text(fitz.Point(70, 90), "NEET NATIONAL ENTRANCE TRIAL 2026 - SECTION A: PHYSICS", fontsize=12)
    p1.insert_text(fitz.Point(70, 150), "Q1. Calculate the relativistic momentum of particle Alpha.", fontsize=10)

    # Page 2: Chemistry with vector lines & question
    p2 = doc.new_page(width=595, height=842)
    p2.draw_line(fitz.Point(50, 80), fitz.Point(545, 80), color=(0.8, 0.2, 0.2), width=2)
    p2.insert_text(fitz.Point(70, 110), "SECTION B: ORGANIC CHEMISTRY & MOLECULAR STRUCTURE", fontsize=12)
    p2.insert_text(fitz.Point(70, 150), "Q2. Identify the rate-determining transition state intermediate.", fontsize=10)

    doc.save(str(source_pdf_path))
    doc.close()

    # Verify source document has NO fingerprint
    source_text = document_parser.extract_text_from_pdf(source_pdf_path)
    assert fingerprint.decode_fingerprint(source_text) is None

    # Embed watermark for NEET-DEMO-042
    recipient = Recipient(recipient_uid="NEET-DEMO-042", name="Dr. A. Sharma", center="Bhopal Center 501")
    output_pdf_path = tmp_path / "personalized_exam.pdf"

    pdf_generator.embed_fingerprint_in_pdf(
        source_pdf=source_pdf_path,
        recipient=recipient,
        output_path=output_pdf_path,
    )

    assert output_pdf_path.exists()
    assert output_pdf_path.stat().st_size > 0

    # Verify pages and visual content are preserved
    out_doc = fitz.open(str(output_pdf_path))
    assert len(out_doc) == 2
    # Verify visible text still exists on both pages
    p1_text = out_doc[0].get_text("text")
    p2_text = out_doc[1].get_text("text")
    out_doc.close()

    assert "SECTION A: PHYSICS" in p1_text
    assert "SECTION B: ORGANIC CHEMISTRY" in p2_text

    # Verify round-trip watermark extraction and source attribution
    extracted_full = document_parser.extract_text_from_pdf(output_pdf_path)
    recovered_uid = fingerprint.decode_fingerprint(extracted_full)
    assert recovered_uid == "NEET-DEMO-042"


# Test 12: embed_fingerprint_in_pdf accepts bytes and path
def test_12_embed_fingerprint_in_pdf_accepts_bytes(tmp_path: Path):
    """Verify embed_fingerprint_in_pdf works identically when passed raw bytes."""
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    page.insert_text(fitz.Point(50, 50), "Test Document for Bytes Stream Injection", fontsize=11)
    raw_bytes = doc.tobytes()
    doc.close()

    recipient = Recipient(recipient_uid="UPSC-DEMO-088", name="Officer R. Verma", center="Delhi Center 102")
    output_path = tmp_path / "watermarked_bytes.pdf"

    pdf_generator.embed_fingerprint_in_pdf(
        source_pdf=raw_bytes,
        recipient=recipient,
        output_path=output_path,
    )

    extracted = document_parser.extract_text_from_pdf(output_path)
    assert fingerprint.decode_fingerprint(extracted) == "UPSC-DEMO-088"


# Test 13: embed_fingerprint_in_pdf error handling for empty and corrupt PDFs
def test_13_embed_fingerprint_in_pdf_error_handling(tmp_path: Path):
    """Verify embed_fingerprint_in_pdf handles 0-byte, corrupt, and missing files with clear errors."""
    recipient = Recipient(recipient_uid="TEST-RECIPIENT", name="Test Recipient", center="Center 1")
    output_path = tmp_path / "out.pdf"

    # Empty bytes
    with pytest.raises(ValueError, match="empty"):
        pdf_generator.embed_fingerprint_in_pdf(b"", recipient, output_path)

    # Empty file
    empty_file = tmp_path / "empty.pdf"
    empty_file.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        pdf_generator.embed_fingerprint_in_pdf(empty_file, recipient, output_path)

    # Corrupt bytes
    with pytest.raises(ValueError, match="Corrupted or invalid"):
        pdf_generator.embed_fingerprint_in_pdf(b"not a real pdf content", recipient, output_path)

    # Missing file
    missing_file = tmp_path / "does_not_exist.pdf"
    with pytest.raises(FileNotFoundError):
        pdf_generator.embed_fingerprint_in_pdf(missing_file, recipient, output_path)

