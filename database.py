"""
database.py - SQLite database layer for CANARYDOCS.

Responsible strictly for SQLite database schema definitions and persistence operations.
Only database.py executes SQL.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional, Union

from models import Document, FingerprintRecord, Recipient

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "canarydocs.db"
_active_db_path: Optional[Path] = None

# Canonical SQLite DDL Schemas
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_name TEXT NOT NULL,
    document_type TEXT NOT NULL,
    original_text TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_uid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    center TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    FOREIGN KEY (document_id) REFERENCES documents (id),
    FOREIGN KEY (recipient_id) REFERENCES recipients (id)
);
"""


def resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve the active database path.

    Args:
        db_path: Optional explicit database path.

    Returns:
        Path instance pointing to target SQLite database.
    """
    if db_path is not None:
        return Path(db_path)
    if _active_db_path is not None:
        return _active_db_path
    return DEFAULT_DB_PATH


def set_default_db_path(db_path: Union[str, Path]) -> None:
    """Override the default database path globally (useful for testing).

    Args:
        db_path: Path to target database.
    """
    global _active_db_path
    _active_db_path = Path(db_path)


def reset_default_db_path() -> None:
    """Reset the default database path to data/canarydocs.db."""
    global _active_db_path
    _active_db_path = None


@contextmanager
def get_connection(
    db_path: Optional[Union[str, Path]] = None,
) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite database connections.

    Ensures foreign keys are enabled, commits transactions on success,
    rolls back on failure, and always closes the connection.
    Does not keep a global open connection.

    Args:
        db_path: Path to the SQLite database file.

    Yields:
        Configured sqlite3.Connection with row_factory enabled.
    """
    target = resolve_db_path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db_connection(
    db_path: Optional[Union[str, Path]] = None,
) -> sqlite3.Connection:
    """Establish and return an SQLite connection with foreign keys enabled.

    Args:
        db_path: Path to database.

    Returns:
        Configured sqlite3.Connection object.
    """
    target = resolve_db_path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_database(db_path: Optional[Union[str, Path]] = None) -> None:
    """Initialize SQLite database and create required tables if they do not exist.

    Safe to call repeatedly; does not destroy existing data.
    Automatically creates the parent directory if needed.

    Args:
        db_path: Path to the SQLite database file. Defaults to data/canarydocs.db.
    """
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)


# Alias for backward compatibility
init_db = init_database


# ==============================================================================
# Recipient Operations
# ==============================================================================


def create_recipient(
    recipient_uid: str,
    name: str,
    center: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Recipient:
    """Insert a recipient record into the database.

    If a recipient with the given recipient_uid already exists, do not create a
    duplicate. Instead, return the existing recipient.

    Args:
        recipient_uid: Unique string identifier for the recipient.
        name: Full name of recipient.
        center: Department, division, or organizational center.
        db_path: Path to database.

    Returns:
        Recipient instance (newly inserted or existing).
    """
    existing = get_recipient_by_uid(recipient_uid, db_path=db_path)
    if existing is not None:
        return existing

    try:
        with get_connection(db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO recipients (recipient_uid, name, center) VALUES (?, ?, ?)",
                (recipient_uid, name, center),
            )
            recipient_id = cursor.lastrowid
            return Recipient(
                id=recipient_id,
                recipient_uid=recipient_uid,
                name=name,
                center=center,
            )
    except sqlite3.IntegrityError:
        # Handle race condition where recipient was inserted concurrently
        existing = get_recipient_by_uid(recipient_uid, db_path=db_path)
        if existing is not None:
            return existing
        raise


def get_recipient_by_uid(
    recipient_uid: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Recipient]:
    """Retrieve a recipient by unique recipient_uid.

    Args:
        recipient_uid: Unique string identifier for the recipient.
        db_path: Path to database.

    Returns:
        Recipient instance if found, None otherwise.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id, recipient_uid, name, center FROM recipients WHERE recipient_uid = ?",
            (recipient_uid,),
        ).fetchone()

    if row is None:
        return None

    return Recipient(
        id=row["id"],
        recipient_uid=row["recipient_uid"],
        name=row["name"],
        center=row["center"],
    )


def get_recipient_by_id(
    recipient_id: int,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Recipient]:
    """Retrieve a recipient by primary key ID.

    Args:
        recipient_id: Primary key ID of the recipient.
        db_path: Path to database.

    Returns:
        Recipient instance if found, None otherwise.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id, recipient_uid, name, center FROM recipients WHERE id = ?",
            (recipient_id,),
        ).fetchone()

    if row is None:
        return None

    return Recipient(
        id=row["id"],
        recipient_uid=row["recipient_uid"],
        name=row["name"],
        center=row["center"],
    )


def list_recipients(
    db_path: Optional[Union[str, Path]] = None,
) -> list[Recipient]:
    """Retrieve all registered recipients from the database.

    Args:
        db_path: Path to database.

    Returns:
        List of Recipient instances.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, recipient_uid, name, center FROM recipients ORDER BY id ASC"
        ).fetchall()

    return [
        Recipient(
            id=row["id"],
            recipient_uid=row["recipient_uid"],
            name=row["name"],
            center=row["center"],
        )
        for row in rows
    ]


# ==============================================================================
# Document Operations
# ==============================================================================


def create_document(
    document_name: str,
    document_type: str,
    original_text: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Document:
    """Insert a new confidential document record into the database.

    Args:
        document_name: Title or filename of the document.
        document_type: Classification or category.
        original_text: Unmodified canonical text of the document.
        db_path: Path to database.

    Returns:
        Document instance with persisted id and created_at timestamp.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO documents (document_name, document_type, original_text, created_at) "
            "VALUES (?, ?, ?, ?)",
            (document_name, document_type, original_text, created_at),
        )
        document_id = cursor.lastrowid

    return Document(
        id=document_id,
        document_name=document_name,
        document_type=document_type,
        original_text=original_text,
        created_at=created_at,
    )


def get_document_by_id(
    document_id: int,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Document]:
    """Retrieve a document by primary key ID.

    Args:
        document_id: Primary key ID of the document.
        db_path: Path to database.

    Returns:
        Document instance if found, None otherwise.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id, document_name, document_type, original_text, created_at "
            "FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()

    if row is None:
        return None

    return Document(
        id=row["id"],
        document_name=row["document_name"],
        document_type=row["document_type"],
        original_text=row["original_text"],
        created_at=row["created_at"],
    )


def list_documents(
    db_path: Optional[Union[str, Path]] = None,
) -> list[Document]:
    """Retrieve all tracked documents from the database.

    Args:
        db_path: Path to database.

    Returns:
        List of Document instances.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, document_name, document_type, original_text, created_at "
            "FROM documents ORDER BY id ASC"
        ).fetchall()

    return [
        Document(
            id=row["id"],
            document_name=row["document_name"],
            document_type=row["document_type"],
            original_text=row["original_text"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


def delete_document(
    document_id: int,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Delete a document and cascade-delete its associated fingerprints.

    Preserves other documents, recipients, and unrelated records.
    Safely respects SQLite foreign key constraints.

    Args:
        document_id: Primary key ID of the document to delete.
        db_path: Path to database.

    Returns:
        True if the document existed and was deleted, False otherwise.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()
        if row is None:
            return False

        # First delete all associated fingerprints to prevent FK violation or orphaned records
        conn.execute(
            "DELETE FROM fingerprints WHERE document_id = ?",
            (document_id,),
        )
        # Delete the document record
        conn.execute(
            "DELETE FROM documents WHERE id = ?",
            (document_id,),
        )
        return True



# ==============================================================================
# Fingerprint Operations
# ==============================================================================


def save_fingerprint(
    document_id: int,
    recipient_id: int,
    fingerprint: str,
    db_path: Optional[Union[str, Path]] = None,
) -> FingerprintRecord:
    """Save an issued fingerprint record into the database.

    Enforces foreign keys to ensure valid document_id and recipient_id.
    Enforces uniqueness of the fingerprint string.

    Args:
        document_id: ID of the referenced document.
        recipient_id: ID of the referenced recipient.
        fingerprint: Unique fingerprint identifier string.
        db_path: Path to database.

    Returns:
        FingerprintRecord instance with persisted id and issued_at timestamp.

    Raises:
        sqlite3.IntegrityError: If foreign keys are violated or fingerprint is duplicate.
    """
    issued_at = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO fingerprints (document_id, recipient_id, fingerprint, issued_at) "
            "VALUES (?, ?, ?, ?)",
            (document_id, recipient_id, fingerprint, issued_at),
        )
        record_id = cursor.lastrowid

    return FingerprintRecord(
        id=record_id,
        document_id=document_id,
        recipient_id=recipient_id,
        fingerprint=fingerprint,
        issued_at=issued_at,
    )


def find_fingerprint(
    fingerprint: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[FingerprintRecord]:
    """Lookup a fingerprint record by its exact fingerprint token/hash.

    Args:
        fingerprint: Fingerprint string to find.
        db_path: Path to database.

    Returns:
        FingerprintRecord instance if found, None otherwise.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id, document_id, recipient_id, fingerprint, issued_at "
            "FROM fingerprints WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()

    if row is None:
        return None

    return FingerprintRecord(
        id=row["id"],
        document_id=row["document_id"],
        recipient_id=row["recipient_id"],
        fingerprint=row["fingerprint"],
        issued_at=row["issued_at"],
    )


# Aliases for compatibility
create_fingerprint = save_fingerprint
get_fingerprint_by_hash = find_fingerprint


def get_fingerprints_for_document(
    document_id: int,
    db_path: Optional[Union[str, Path]] = None,
) -> list[FingerprintRecord]:
    """Retrieve all fingerprint issuances associated with a given document.

    Args:
        document_id: ID of the document.
        db_path: Path to database.

    Returns:
        List of FingerprintRecord instances.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, document_id, recipient_id, fingerprint, issued_at "
            "FROM fingerprints WHERE document_id = ? ORDER BY id ASC",
            (document_id,),
        ).fetchall()

    return [
        FingerprintRecord(
            id=row["id"],
            document_id=row["document_id"],
            recipient_id=row["recipient_id"],
            fingerprint=row["fingerprint"],
            issued_at=row["issued_at"],
        )
        for row in rows
    ]


def list_fingerprints(
    db_path: Optional[Union[str, Path]] = None,
) -> list[FingerprintRecord]:
    """Retrieve all issued fingerprint records from the database.

    Args:
        db_path: Path to database.

    Returns:
        List of FingerprintRecord instances.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, document_id, recipient_id, fingerprint, issued_at "
            "FROM fingerprints ORDER BY id DESC"
        ).fetchall()

    return [
        FingerprintRecord(
            id=row["id"],
            document_id=row["document_id"],
            recipient_id=row["recipient_id"],
            fingerprint=row["fingerprint"],
            issued_at=row["issued_at"],
        )
        for row in rows
    ]


def get_audit_records(
    db_path: Optional[Union[str, Path]] = None,
) -> list[dict]:
    """Retrieve joined audit records containing document, recipient, and fingerprint details.

    Args:
        db_path: Path to database.

    Returns:
        List of dictionaries with joined metadata.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT 
                f.id AS fingerprint_id,
                f.fingerprint AS fingerprint_token,
                f.issued_at,
                d.id AS document_id,
                d.document_name,
                d.document_type,
                r.id AS recipient_id,
                r.recipient_uid,
                r.name AS recipient_name,
                r.center AS recipient_center
            FROM fingerprints f
            JOIN documents d ON f.document_id = d.id
            JOIN recipients r ON f.recipient_id = r.id
            ORDER BY f.id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def clear_all_tables(db_path: Optional[Union[str, Path]] = None) -> None:
    """Clear all records from documents, recipients, and fingerprints tables."""
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM fingerprints")
        conn.execute("DELETE FROM recipients")
        conn.execute("DELETE FROM documents")


# ==============================================================================
# Dashboard Statistics
# ==============================================================================


def get_dashboard_stats(
    db_path: Optional[Union[str, Path]] = None,
) -> dict[str, int]:
    """Retrieve aggregated counts for the dashboard overview.

    Returns:
        Dictionary containing counts for:
            - documents_issued (total documents registered/issued)
            - recipients (total registered recipients)
            - fingerprints (total issued fingerprints)
            - investigations (0 until investigations persistence is added)
    """
    with get_connection(db_path) as conn:
        docs_count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        recipients_count = conn.execute("SELECT COUNT(*) FROM recipients").fetchone()[0]
        fingerprints_count = conn.execute(
            "SELECT COUNT(*) FROM fingerprints"
        ).fetchone()[0]

    return {
        "documents_issued": docs_count,
        "recipients": recipients_count,
        "fingerprints": fingerprints_count,
        "investigations": 0,
    }
