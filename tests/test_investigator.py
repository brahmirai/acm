"""
test_investigator.py - Integration and unit tests for the leak investigation engine.

Verifies:
1. Critical End-to-End Test: Known recipient/document in PDF resolves to NEET-DEMO-042.
2. Known fingerprint in TXT document resolves to registered source.
3. Unknown fingerprint (valid CanaryDocs watermark but not registered in database)
   returns matched=False and "Fingerprint detected but source not registered".
4. No fingerprint in PDF/TXT returns matched=False and fingerprint=None.
5. Different recipients (NEET-DEMO-042 vs NEET-DEMO-043) resolve independently.
6. Error cases (missing file, unsupported format, empty document) handled safely.

All tests operate in isolated temporary directories with temporary SQLite databases.
"""

from pathlib import Path
import pytest

import database
import fingerprint
import investigator
from models import Document, InvestigationResult, Recipient
import pdf_generator


@pytest.fixture
def inv_db(tmp_path: Path) -> Path:
    """Create a temporary initialized SQLite database for investigator tests."""
    db_file = tmp_path / "investigator_test.db"
    database.init_database(db_file)
    return db_file


# 1. Critical End-to-End Test: Real PDF Leak Investigation
def test_1_critical_end_to_end_known_pdf_fingerprint(tmp_path: Path, inv_db: Path):
    """TEST 1 & CRITICAL E2E: Real PDF investigation resolves NEET-DEMO-042 to Demo Candidate."""
    # 1. Setup canonical document in SQLite
    doc_model = pdf_generator.create_demo_neet_document()
    doc_record = database.create_document(
        document_name=doc_model.document_name,
        document_type=doc_model.document_type,
        original_text=doc_model.original_text,
        db_path=inv_db,
    )

    # 2. Setup registered recipient
    rec_record = database.create_recipient(
        recipient_uid="NEET-DEMO-042",
        name="Demo Candidate",
        center="Block B",
        db_path=inv_db,
    )

    # 3. Save fingerprint mapping in database
    database.save_fingerprint(
        document_id=doc_record.id,
        recipient_id=rec_record.id,
        fingerprint="NEET-DEMO-042",
        db_path=inv_db,
    )

    # 4. Generate physical canary PDF
    pdf_file = tmp_path / "leaked_neet_exam.pdf"
    pdf_generator.generate_personalized_pdf(
        document=doc_record,
        recipient=rec_record,
        output_path=pdf_file,
    )

    # 5. Run investigator on leaked PDF
    result = investigator.investigate_document(pdf_file, db_path=inv_db)

    # 6. Verify full forensic resolution
    assert result.matched is True
    assert result.is_match is True
    assert result.status == investigator.STATE_SOURCE_IDENTIFIED
    assert result.fingerprint == "NEET-DEMO-042"

    assert result.recipient is not None
    assert result.recipient.recipient_uid == "NEET-DEMO-042"
    assert result.recipient.name == "Demo Candidate"
    assert result.recipient.center == "Block B"

    assert result.document is not None
    assert result.document.document_name == "NEET Mock Examination 2026"
    assert "CANDIDATE INSTRUCTIONS" in result.extracted_text
    assert "CANDIDATE INSTRUCTIONS" in result.cleaned_text


# 2. Known Fingerprint from Plaintext (TXT)
def test_2_known_fingerprint_from_txt(tmp_path: Path, inv_db: Path):
    """TEST 2: TXT document with embedded fingerprint resolves to registered source."""
    doc = database.create_document("Intelligence Brief", "SECRET", "Operation Falcon details.", db_path=inv_db)
    rec = database.create_recipient("AGENT-007", "James Bond", "London Station", db_path=inv_db)
    database.save_fingerprint(doc.id, rec.id, "AGENT-007", db_path=inv_db)

    # Encode fingerprint into text and save as TXT
    encoded_text = fingerprint.encode_text(doc.original_text, rec.recipient_uid)
    txt_file = tmp_path / "leaked_brief.txt"
    txt_file.write_text(encoded_text, encoding="utf-8")

    result = investigator.investigate_document(txt_file, db_path=inv_db)

    assert result.matched is True
    assert result.fingerprint == "AGENT-007"
    assert result.recipient is not None
    assert result.recipient.name == "James Bond"
    assert result.document is not None
    assert result.document.document_name == "Intelligence Brief"
    assert result.message == investigator.MSG_SOURCE_IDENTIFIED


# 3. Unknown Fingerprint (Valid Steganography but Unregistered in Database)
def test_3_unknown_unregistered_fingerprint(tmp_path: Path, inv_db: Path):
    """TEST 3: Valid CanaryDocs fingerprint not in SQLite must NOT guess source."""
    raw_text = "CONFIDENTIAL INTERNAL PROTOCOL\nRestricted access only."
    rogue_fp = "ROGUE-UNREGISTERED-999"
    encoded_text = fingerprint.encode_text(raw_text, rogue_fp)

    txt_file = tmp_path / "rogue_document.txt"
    txt_file.write_text(encoded_text, encoding="utf-8")

    result = investigator.investigate_document(txt_file, db_path=inv_db)

    # Must NOT guess a recipient
    assert result.matched is False
    assert result.is_match is False
    assert result.status == investigator.STATE_FINGERPRINT_UNKNOWN
    assert result.fingerprint == rogue_fp
    assert result.recipient is None
    assert result.document is None
    assert result.message == "Fingerprint detected but source not registered."


# 4. No Fingerprint in Document
def test_4_no_fingerprint_in_document(tmp_path: Path, inv_db: Path):
    """TEST 4: Document with no steganography returns matched=False and fingerprint=None."""
    clean_text = "Plain unwatermarked document text with no zero-width characters."
    txt_file = tmp_path / "unwatermarked.txt"
    txt_file.write_text(clean_text, encoding="utf-8")

    result = investigator.investigate_document(txt_file, db_path=inv_db)

    assert result.matched is False
    assert result.is_match is False
    assert result.status == investigator.STATE_NO_FINGERPRINT
    assert result.fingerprint is None
    assert result.recipient is None
    assert result.document is None
    assert result.message == "No provenance fingerprint detected."


# 5. Multiple Distinct Recipients
def test_5_multiple_distinct_recipients(tmp_path: Path, inv_db: Path):
    """TEST 5: Verify different recipients resolve strictly to their own identities."""
    doc = database.create_document("Exam Paper", "EXAM", "Standard questions.", db_path=inv_db)

    rec_42 = database.create_recipient("NEET-DEMO-042", "Candidate 42", "Center 42", db_path=inv_db)
    rec_43 = database.create_recipient("NEET-DEMO-043", "Candidate 43", "Center 43", db_path=inv_db)

    database.save_fingerprint(doc.id, rec_42.id, "NEET-DEMO-042", db_path=inv_db)
    database.save_fingerprint(doc.id, rec_43.id, "NEET-DEMO-043", db_path=inv_db)

    pdf_42 = tmp_path / "exam_42.pdf"
    pdf_43 = tmp_path / "exam_43.pdf"

    pdf_generator.generate_personalized_pdf(doc, rec_42, pdf_42)
    pdf_generator.generate_personalized_pdf(doc, rec_43, pdf_43)

    res_42 = investigator.investigate_document(pdf_42, db_path=inv_db)
    res_43 = investigator.investigate_document(pdf_43, db_path=inv_db)

    assert res_42.matched is True
    assert res_42.recipient.recipient_uid == "NEET-DEMO-042"
    assert res_42.recipient.name == "Candidate 42"

    assert res_43.matched is True
    assert res_43.recipient.recipient_uid == "NEET-DEMO-043"
    assert res_43.recipient.name == "Candidate 43"


# 6. Error & Malformed Input Handling
def test_6_error_and_malformed_input(tmp_path: Path, inv_db: Path):
    """TEST 6: Invalid/missing files and unsupported formats return structured ERROR states."""
    # 1. Non-existent file
    missing = tmp_path / "missing_file.pdf"
    res_missing = investigator.investigate_document(missing, db_path=inv_db)
    assert res_missing.matched is False
    assert res_missing.status == investigator.STATE_ERROR
    assert "not found" in res_missing.message.lower()

    # 2. Unsupported file extension
    unsupported = tmp_path / "image.png"
    unsupported.write_bytes(b"\x89PNG\r\n\x1a\n")
    res_unsupported = investigator.investigate_document(unsupported, db_path=inv_db)
    assert res_unsupported.matched is False
    assert res_unsupported.status == investigator.STATE_ERROR
    assert "unsupported" in res_unsupported.message.lower()

    # 3. Empty document
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("", encoding="utf-8")
    res_empty = investigator.investigate_document(empty_file, db_path=inv_db)
    assert res_empty.matched is False
    assert res_empty.status == investigator.STATE_NO_FINGERPRINT
    assert res_empty.fingerprint is None

    # 4. Raw text None input
    res_none = investigator.investigate_raw_text(None, db_path=inv_db)
    assert res_none.matched is False
    assert res_none.status == investigator.STATE_ERROR
