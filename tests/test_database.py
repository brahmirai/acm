"""
test_database.py - Comprehensive persistence layer tests for CANARYDOCS.

Verifies:
1. Database initialization and idempotency
2. Recipient creation
3. Recipient lookup by UID and ID
4. Duplicate recipient behavior (deduplication)
5. Document creation
6. Document lookup and listing
7. Fingerprint creation
8. Fingerprint lookup
9. Foreign key relationships and integrity constraints
10. Dashboard statistics

All tests use temporary SQLite databases isolated from production data.
"""

import sqlite3
from pathlib import Path

import pytest

import database
from models import Document, FingerprintRecord, Recipient


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Provide a fresh, isolated SQLite database initialized for each test."""
    db_file = tmp_path / "test_canarydocs.db"
    database.init_database(db_file)
    return db_file


# 1. Database Initialization
def test_database_initialization(tmp_path: Path):
    """Verify tables are created and repeated initialization does not drop data."""
    db_file = tmp_path / "init_test.db"
    assert not db_file.exists()

    # Initial creation
    database.init_database(db_file)
    assert db_file.exists()

    with database.get_connection(db_file) as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

    assert "documents" in tables
    assert "recipients" in tables
    assert "fingerprints" in tables

    # Insert a dummy record
    rec = database.create_recipient("INIT-01", "Init User", "Center X", db_path=db_file)
    assert rec.id is not None

    # Idempotent re-initialization must not destroy existing data
    database.init_database(db_file)
    found = database.get_recipient_by_uid("INIT-01", db_path=db_file)
    assert found is not None
    assert found.name == "Init User"


# 2. Recipient Creation
def test_recipient_creation(test_db: Path):
    """Verify inserting a recipient creates a properly populated Recipient model."""
    rec = database.create_recipient(
        recipient_uid="REC-001",
        name="Alice Vance",
        center="Cyber Operations",
        db_path=test_db,
    )

    assert rec.id is not None
    assert rec.recipient_uid == "REC-001"
    assert rec.name == "Alice Vance"
    assert rec.center == "Cyber Operations"

    # Confirm persistence in database
    with database.get_connection(test_db) as conn:
        row = conn.execute(
            "SELECT * FROM recipients WHERE id = ?", (rec.id,)
        ).fetchone()
        assert row is not None
        assert row["recipient_uid"] == "REC-001"


# 3. Recipient Lookup by UID & ID
def test_recipient_lookup(test_db: Path):
    """Verify lookup by UID and ID, including negative cases."""
    created = database.create_recipient(
        recipient_uid="REC-002",
        name="Bob Vance",
        center="Logistics Division",
        db_path=test_db,
    )

    # Lookup by UID
    by_uid = database.get_recipient_by_uid("REC-002", db_path=test_db)
    assert by_uid is not None
    assert by_uid.id == created.id
    assert by_uid.name == "Bob Vance"
    assert by_uid.center == "Logistics Division"

    # Lookup by ID
    by_id = database.get_recipient_by_id(created.id, db_path=test_db)
    assert by_id is not None
    assert by_id.recipient_uid == "REC-002"

    # Negative lookups
    assert database.get_recipient_by_uid("NON_EXISTENT_UID", db_path=test_db) is None
    assert database.get_recipient_by_id(999999, db_path=test_db) is None


# 4. Duplicate Recipient Behavior
def test_duplicate_recipient_behavior(test_db: Path):
    """Verify duplicate recipient_uid returns existing record and does not duplicate."""
    original = database.create_recipient(
        recipient_uid="REC-DUP-01",
        name="Charlie Original",
        center="Original Center",
        db_path=test_db,
    )

    # Attempt to create duplicate with same UID but different name/center
    duplicate_call = database.create_recipient(
        recipient_uid="REC-DUP-01",
        name="Charlie Duplicate",
        center="Alternate Center",
        db_path=test_db,
    )

    # Must return the existing recipient instance
    assert duplicate_call.id == original.id
    assert duplicate_call.recipient_uid == "REC-DUP-01"
    assert duplicate_call.name == "Charlie Original"
    assert duplicate_call.center == "Original Center"

    # Total rows in recipients table must remain exactly 1
    all_recipients = database.list_recipients(db_path=test_db)
    assert len(all_recipients) == 1


# 5. Document Creation
def test_document_creation(test_db: Path):
    """Verify document insertion persists fields and generates ISO timestamp."""
    doc = database.create_document(
        document_name="Operation Peregrine",
        document_type="OPERATIONAL_BRIEF",
        original_text="Classified operational parameters for mission alpha.",
        db_path=test_db,
    )

    assert doc.id is not None
    assert doc.document_name == "Operation Peregrine"
    assert doc.document_type == "OPERATIONAL_BRIEF"
    assert doc.original_text == "Classified operational parameters for mission alpha."
    assert doc.created_at is not None
    assert "T" in doc.created_at  # ISO format validation


# 6. Document Lookup and Listing
def test_document_lookup_and_listing(test_db: Path):
    """Verify document retrieval by ID and listing all documents."""
    doc1 = database.create_document("Doc Alpha", "BRIEF", "Content A", db_path=test_db)
    doc2 = database.create_document("Doc Beta", "REPORT", "Content B", db_path=test_db)

    # Lookup by ID
    found1 = database.get_document_by_id(doc1.id, db_path=test_db)
    assert found1 is not None
    assert found1.document_name == "Doc Alpha"

    found2 = database.get_document_by_id(doc2.id, db_path=test_db)
    assert found2 is not None
    assert found2.document_name == "Doc Beta"

    # Non-existent ID
    assert database.get_document_by_id(999999, db_path=test_db) is None

    # List all documents
    all_docs = database.list_documents(db_path=test_db)
    assert len(all_docs) == 2
    assert [d.document_name for d in all_docs] == ["Doc Alpha", "Doc Beta"]


# 7. Fingerprint Creation
def test_fingerprint_creation(test_db: Path):
    """Verify saving a fingerprint record maps document and recipient with timestamp."""
    doc = database.create_document("Secret Memo", "MEMO", "Memo body", db_path=test_db)
    rec = database.create_recipient("REC-FP-01", "Dana Scully", "FBI", db_path=test_db)

    fp = database.save_fingerprint(
        document_id=doc.id,
        recipient_id=rec.id,
        fingerprint="FP-HASH-ALPHA-001",
        db_path=test_db,
    )

    assert fp.id is not None
    assert fp.document_id == doc.id
    assert fp.recipient_id == rec.id
    assert fp.fingerprint == "FP-HASH-ALPHA-001"
    assert fp.issued_at is not None


# 8. Fingerprint Lookup
def test_fingerprint_lookup(test_db: Path):
    """Verify finding a fingerprint record by its exact token string."""
    doc = database.create_document("Secret Memo 2", "MEMO", "Memo body 2", db_path=test_db)
    rec = database.create_recipient("REC-FP-02", "Fox Mulder", "FBI", db_path=test_db)
    saved = database.save_fingerprint(doc.id, rec.id, "FP-HASH-BETA-002", db_path=test_db)

    # Positive lookup
    found = database.find_fingerprint("FP-HASH-BETA-002", db_path=test_db)
    assert found is not None
    assert found.id == saved.id
    assert found.document_id == doc.id
    assert found.recipient_id == rec.id

    # Negative lookup
    assert database.find_fingerprint("NON_EXISTENT_FINGERPRINT", db_path=test_db) is None


# 9. Foreign Key Relationships
def test_foreign_key_relationships(test_db: Path):
    """Verify SQLite foreign key enforcement protects document_id and recipient_id integrity."""
    doc = database.create_document("Valid Doc", "BRIEF", "Body", db_path=test_db)
    rec = database.create_recipient("REC-FK-01", "Walter Skinner", "Exec", db_path=test_db)

    # Invalid document_id must violate foreign key
    with pytest.raises(sqlite3.IntegrityError):
        database.save_fingerprint(
            document_id=99999,
            recipient_id=rec.id,
            fingerprint="FP-FAIL-DOC",
            db_path=test_db,
        )

    # Invalid recipient_id must violate foreign key
    with pytest.raises(sqlite3.IntegrityError):
        database.save_fingerprint(
            document_id=doc.id,
            recipient_id=99999,
            fingerprint="FP-FAIL-REC",
            db_path=test_db,
        )

    # Duplicate fingerprint token must violate UNIQUE constraint
    database.save_fingerprint(doc.id, rec.id, "FP-UNIQUE-TEST", db_path=test_db)
    with pytest.raises(sqlite3.IntegrityError):
        database.save_fingerprint(doc.id, rec.id, "FP-UNIQUE-TEST", db_path=test_db)


# 10. Dashboard Statistics
def test_dashboard_statistics(test_db: Path):
    """Verify get_dashboard_stats returns accurate counts as entities are created."""
    # Baseline check on empty database
    initial_stats = database.get_dashboard_stats(db_path=test_db)
    assert initial_stats["documents_issued"] == 0
    assert initial_stats["recipients"] == 0
    assert initial_stats["fingerprints"] == 0
    assert initial_stats["investigations"] == 0

    # Create 2 documents
    doc1 = database.create_document("Doc 1", "BRIEF", "Body 1", db_path=test_db)
    doc2 = database.create_document("Doc 2", "REPORT", "Body 2", db_path=test_db)

    # Create 3 recipients
    rec1 = database.create_recipient("R-01", "Agent 1", "Site A", db_path=test_db)
    rec2 = database.create_recipient("R-02", "Agent 2", "Site B", db_path=test_db)
    rec3 = database.create_recipient("R-03", "Agent 3", "Site C", db_path=test_db)

    # Save 2 fingerprints
    database.save_fingerprint(doc1.id, rec1.id, "FP-TOKEN-01", db_path=test_db)
    database.save_fingerprint(doc1.id, rec2.id, "FP-TOKEN-02", db_path=test_db)

    # Verify updated stats
    updated_stats = database.get_dashboard_stats(db_path=test_db)
    assert updated_stats["documents_issued"] == 2
    assert updated_stats["recipients"] == 3
    assert updated_stats["fingerprints"] == 2
    assert updated_stats["investigations"] == 0


# 11. Document Deletion & Cascade Fingerprint Cleanup
def test_delete_document_success_and_cascade(test_db: Path):
    """Verify document deletion removes the document and cascades to its fingerprints,
    preserving unrelated documents, recipients, and maintaining valid DB constraints."""
    doc1 = database.create_document("Doc to Delete", "CLASSIFIED", "Content 1", db_path=test_db)
    doc2 = database.create_document("Doc to Keep", "RESTRICTED", "Content 2", db_path=test_db)

    rec1 = database.create_recipient("REC-DEL-01", "Alice", "Center A", db_path=test_db)
    rec2 = database.create_recipient("REC-DEL-02", "Bob", "Center B", db_path=test_db)

    # Issue fingerprints for both documents
    fp1 = database.save_fingerprint(doc1.id, rec1.id, "FP-TO-DELETE-1", db_path=test_db)
    fp2 = database.save_fingerprint(doc1.id, rec2.id, "FP-TO-DELETE-2", db_path=test_db)
    fp3 = database.save_fingerprint(doc2.id, rec1.id, "FP-TO-KEEP", db_path=test_db)

    # Verify initial state
    assert len(database.get_fingerprints_for_document(doc1.id, db_path=test_db)) == 2
    assert len(database.get_fingerprints_for_document(doc2.id, db_path=test_db)) == 1

    # Perform deletion of doc1
    result = database.delete_document(doc1.id, db_path=test_db)
    assert result is True

    # doc1 is gone
    assert database.get_document_by_id(doc1.id, db_path=test_db) is None
    # doc1's fingerprints are cleaned up (no orphaned records)
    assert database.get_fingerprints_for_document(doc1.id, db_path=test_db) == []
    assert database.find_fingerprint("FP-TO-DELETE-1", db_path=test_db) is None
    assert database.find_fingerprint("FP-TO-DELETE-2", db_path=test_db) is None

    # doc2 and its fingerprints remain intact
    doc2_retrieved = database.get_document_by_id(doc2.id, db_path=test_db)
    assert doc2_retrieved is not None
    assert doc2_retrieved.document_name == "Doc to Keep"
    assert len(database.get_fingerprints_for_document(doc2.id, db_path=test_db)) == 1
    assert database.find_fingerprint("FP-TO-KEEP", db_path=test_db) is not None

    # Both recipients remain intact
    recipients = database.list_recipients(db_path=test_db)
    assert len(recipients) == 2
    assert any(r.recipient_uid == "REC-DEL-01" for r in recipients)
    assert any(r.recipient_uid == "REC-DEL-02" for r in recipients)

    # Database constraints remain valid: can create new document and fingerprint
    doc3 = database.create_document("Doc 3", "OPEN", "Content 3", db_path=test_db)
    fp_new = database.save_fingerprint(doc3.id, rec1.id, "FP-NEW-01", db_path=test_db)
    assert fp_new.id is not None


def test_delete_document_nonexistent_and_empty_db(test_db: Path):
    """Verify delete_document safely handles non-existent IDs and empty databases."""
    # Empty DB
    assert database.delete_document(99999, db_path=test_db) is False

    # Populated DB with nonexistent ID
    database.create_document("Existing Doc", "BRIEF", "Body", db_path=test_db)
    assert database.delete_document(99999, db_path=test_db) is False

