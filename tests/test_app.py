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


