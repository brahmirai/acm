"""
test_app.py - Integration and contract verification for CANARYDOCS Streamlit UI (app.py).

Verifies:
1. Exported view functions and contract signatures in app.py.
2. App initialization and session state handling.
3. CSS classes and forensic UI styling constants.
4. Database audit records and seeder functionality.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import app
import database
import seed_data


def test_app_contract_signatures():
    """Verify that all core view functions and main entrypoint exist and are callable."""
    assert callable(app.main)
    assert callable(app.render_sidebar)
    assert callable(app.view_document_issuance)
    assert callable(app.view_leak_investigation)
    assert callable(app.view_forensic_analysis)
    assert callable(app.view_audit_log)
    assert callable(app.initialize_app_state)


def test_app_custom_css_forensic_classes():
    """Verify custom CSS defines forensic scorecards and severity styles."""
    css = app.CUSTOM_CSS
    assert "badge-confirmed" in css
    assert "badge-unknown" in css
    assert "badge-nofp" in css
    assert "severity-critical" in css
    assert "severity-high" in css
    assert "forensic-card" in css


def test_seed_database_fixture(tmp_path: Path):
    """Verify seed_database populates standard demonstration records."""
    db_file = tmp_path / "test_canary.db"
    result = seed_data.seed_database(db_path=db_file, force=True)

    assert len(result["documents"]) >= 2
    assert len(result["recipients"]) >= 3

    # Verify NEET and UPSC fixtures exist
    doc_names = [d.document_name for d in result["documents"]]
    assert any("NEET" in name for name in doc_names)
    assert any("UPSC" in name for name in doc_names)

    # Verify NEET-DEMO-042 recipient exists
    rec_uids = [r.recipient_uid for r in result["recipients"]]
    assert "NEET-DEMO-042" in rec_uids
    assert "NEET-DEMO-088" in rec_uids


def test_database_audit_records_query(tmp_path: Path):
    """Verify database.get_audit_records correctly joins documents, recipients, and fingerprints."""
    db_file = tmp_path / "test_audit.db"
    seed = seed_data.seed_database(db_path=db_file, force=True)

    doc = seed["documents"][0]
    rec = seed["recipients"][0]

    # Create an issuance record
    database.create_fingerprint(
        document_id=doc.id,
        recipient_id=rec.id,
        fingerprint=rec.recipient_uid,
        db_path=db_file,
    )

    records = database.get_audit_records(db_path=db_file)
    assert len(records) == 1
    record = records[0]
    assert record["fingerprint_token"] == rec.recipient_uid
    assert record["document_name"] == doc.document_name
    assert record["recipient_name"] == rec.name
    assert record["recipient_uid"] == rec.recipient_uid


def test_format_detected_value():
    """Verify boolean and string detection flag conversions to 'Yes' and 'No'."""
    assert app._format_detected_value(True) == "Yes"
    assert app._format_detected_value(False) == "No"
    assert app._format_detected_value("true") == "Yes"
    assert app._format_detected_value("True") == "Yes"
    assert app._format_detected_value("yes") == "Yes"
    assert app._format_detected_value("false") == "No"
    assert app._format_detected_value("False") == "No"
    assert app._format_detected_value("no") == "No"
    assert app._format_detected_value(None) == "No"
    assert app._format_detected_value(1) == "Yes"
    assert app._format_detected_value(0) == "No"


def test_format_structured_detection_lines_dict():
    """Verify structured dictionary renders actual Detected and Explanation values, not raw keys."""
    # Detection detected = True
    data_true = {
        "detected": True,
        "explanation": "Significant paraphrasing observed in Section B.",
    }
    lines_true = app._format_structured_detection_lines(data_true)
    assert "- **Detected:** Yes" in lines_true
    assert "- **Explanation:** Significant paraphrasing observed in Section B." in lines_true
    # Verify the old bug (displaying only raw dict keys) is resolved
    assert "- 🔍 detected" not in lines_true
    assert "- 🔍 explanation" not in lines_true

    # Detection detected = False
    data_false = {
        "detected": False,
        "explanation": "No redactions detected in the document.",
    }
    lines_false = app._format_structured_detection_lines(data_false)
    assert "- **Detected:** No" in lines_false
    assert "- **Explanation:** No redactions detected in the document." in lines_false


def test_format_structured_detection_lines_object():
    """Verify structured object with attributes renders Detected and Explanation clearly."""
    class MockDetection:
        def __init__(self, detected, explanation):
            self.detected = detected
            self.explanation = explanation

    obj = MockDetection(True, "Candidate markings omitted.")
    lines = app._format_structured_detection_lines(obj)
    assert "- **Detected:** Yes" in lines
    assert "- **Explanation:** Candidate markings omitted." in lines


def test_format_structured_detection_lines_empty_and_list():
    """Verify empty values and list values are handled gracefully."""
    empty_lines = app._format_structured_detection_lines({}, empty_label="No sensitive sections appear redacted")
    assert empty_lines == ["*(No sensitive sections appear redacted)*"]

    none_lines = app._format_structured_detection_lines(None, empty_label="No paraphrasing found")
    assert none_lines == ["*(No paraphrasing found)*"]

    list_dicts = [
        {"detected": True, "explanation": "Item 1 altered."},
        {"detected": False, "explanation": "Item 2 intact."},
    ]
    list_lines = app._format_structured_detection_lines(list_dicts)
    assert "- **Detected:** Yes" in list_lines
    assert "  - **Explanation:** Item 1 altered." in list_lines
    assert "- **Detected:** No" in list_lines
    assert "  - **Explanation:** Item 2 intact." in list_lines


def test_audit_log_view_empty_database(tmp_path: Path, monkeypatch):
    """Verify that view_audit_log does not crash when database is completely empty."""
    empty_db = tmp_path / "empty_audit.db"
    database.init_db(db_path=empty_db)
    monkeypatch.setattr(database, "DEFAULT_DB_PATH", empty_db)

    try:
        app.view_audit_log()
    except Exception as exc:
        pytest.fail(f"view_audit_log crashed on empty database: {exc}")


def test_audit_log_view_populated_database(tmp_path: Path, monkeypatch):
    """Verify that view_audit_log executes cleanly with populated records."""
    pop_db = tmp_path / "populated_audit.db"
    seed = seed_data.seed_database(db_path=pop_db, force=True)
    doc = seed["documents"][0]
    rec = seed["recipients"][0]
    database.create_fingerprint(doc.id, rec.id, rec.recipient_uid, db_path=pop_db)
    monkeypatch.setattr(database, "DEFAULT_DB_PATH", pop_db)

    try:
        app.view_audit_log()
    except Exception as exc:
        pytest.fail(f"view_audit_log crashed on populated database: {exc}")


def test_corrupted_pdf_investigation_handling(tmp_path: Path):
    """Verify corrupted/malformed PDF returns structured ERROR without crashing."""
    import investigator

    corrupt_pdf = tmp_path / "corrupted.pdf"
    corrupt_pdf.write_bytes(b"%PDF-1.4 malformed header and corrupted binary garbage \x00\xff\xfe")

    result = investigator.investigate_document(corrupt_pdf)
    assert result.matched is False
    assert result.status == investigator.STATE_ERROR
    assert "Corrupted or invalid PDF file" in result.message
    assert result.fingerprint is None


def test_empty_files_investigation_handling(tmp_path: Path):
    """Verify 0-byte PDF and TXT files return STATE_NO_FINGERPRINT gracefully."""
    import investigator

    empty_pdf = tmp_path / "empty.pdf"
    empty_pdf.write_bytes(b"")

    res_pdf = investigator.investigate_document(empty_pdf)
    assert res_pdf.matched is False
    assert res_pdf.status == investigator.STATE_NO_FINGERPRINT
    assert res_pdf.fingerprint is None
    assert "empty" in res_pdf.details.lower()

    empty_txt = tmp_path / "empty.txt"
    empty_txt.write_text("", encoding="utf-8")

    res_txt = investigator.investigate_document(empty_txt)
    assert res_txt.matched is False
    assert res_txt.status == investigator.STATE_NO_FINGERPRINT
    assert res_txt.fingerprint is None
    assert "empty" in res_txt.details.lower()


def test_unsupported_file_extension_handling(tmp_path: Path):
    """Verify unsupported file types return structured ERROR with informative message."""
    import investigator

    unsupported_file = tmp_path / "leak.docx"
    unsupported_file.write_bytes(b"PK\x03\x04 fake docx")

    result = investigator.investigate_document(unsupported_file)
    assert result.matched is False
    assert result.status == investigator.STATE_ERROR
    assert "Unsupported document format" in result.message
    assert ".docx" in result.message


def test_gemini_empty_text_safeguards():
    """Verify Gemini forensic analysis handles empty inputs without calling API."""
    import gemini_service

    # Empty original
    rep1 = gemini_service.analyze_incident(original_text="", leaked_text="leaked content")
    assert rep1.severity == "LOW"
    assert "empty" in rep1.summary.lower()
    assert rep1.possible_paraphrasing["detected"] is False

    # Empty leaked
    rep2 = gemini_service.analyze_incident(original_text="original content", leaked_text="")
    assert rep2.severity == "LOW"
    assert "empty" in rep2.summary.lower()
    assert rep2.possible_redactions["detected"] is True


def test_gemini_api_key_sanitization_and_friendly_messages():
    """Verify API errors redact leaked API keys and provide friendly summaries for 429 and 401."""
    import gemini_service
    from unittest.mock import MagicMock

    # Test 429 Quota Exceeded with embedded API key
    fake_key = "AIzaSyB1234567890abcdef1234567890abcdef"
    mock_client_429 = MagicMock()
    mock_client_429.models.generate_content.side_effect = RuntimeError(
        f"Request to https://generativelanguage.googleapis.com/v1beta?key={fake_key} failed: 429 RESOURCE_EXHAUSTED"
    )

    report_429 = gemini_service.analyze_incident(
        original_text="Original text",
        leaked_text="Leaked text",
        client=mock_client_429,
    )
    assert fake_key not in report_429.impact
    assert fake_key not in report_429.raw_analysis
    assert "[REDACTED_API_KEY]" in report_429.impact
    assert "rate limit or quota exceeded (429)" in report_429.summary

    # Test 401 Invalid Key
    mock_client_401 = MagicMock()
    mock_client_401.models.generate_content.side_effect = RuntimeError(
        f"Error 401 API_KEY_INVALID for key={fake_key}"
    )

    report_401 = gemini_service.analyze_incident(
        original_text="Original text",
        leaked_text="Leaked text",
        client=mock_client_401,
    )
    assert fake_key not in report_401.impact
    assert "[REDACTED_API_KEY]" in report_401.impact
    assert "Invalid or unauthorized Gemini API key" in report_401.summary


def test_gemini_missing_api_key_error(monkeypatch):
    """Verify get_gemini_client raises ValueError with informative message when key is missing."""
    import gemini_service

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY is not set"):
        gemini_service.get_gemini_client(api_key=None)



