"""
investigator.py - Leak investigation and fingerprint lookup engine for CANARYDOCS.

Coordinates the complete digital document investigation pipeline:
uploaded PDF/TXT
    ↓
extract text (document_parser.extract_document_text)
    ↓
decode zero-width fingerprint (fingerprint.decode_fingerprint)
    ↓
look up fingerprint in SQLite (database.find_fingerprint)
    ↓
identify registered document (database.get_document_by_id)
    ↓
identify recipient (database.get_recipient_by_id)
    ↓
return structured InvestigationResult

CRITICAL FORENSIC RULE:
The investigator must NEVER guess a recipient. If a fingerprint is absent or unregistered,
matched attribution remains strictly False.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

import database
import document_parser
import fingerprint
from models import Document, InvestigationResult, Recipient

# Forensic Investigation States
STATE_SOURCE_IDENTIFIED = "SOURCE IDENTIFIED"
STATE_FINGERPRINT_UNKNOWN = "FINGERPRINT DETECTED — SOURCE UNKNOWN"
STATE_NO_FINGERPRINT = "NO PROVENANCE FINGERPRINT DETECTED"
STATE_ERROR = "ERROR"

# Canonical State Messages
MSG_SOURCE_IDENTIFIED = "SOURCE IDENTIFIED"
MSG_FINGERPRINT_UNKNOWN = "Fingerprint detected but source not registered."
MSG_NO_FINGERPRINT = "No provenance fingerprint detected."


def investigate_raw_text(
    text: str, db_path: Optional[Union[str, Path]] = None
) -> InvestigationResult:
    """Investigate raw text string for zero-width provenance fingerprints.

    Args:
        text: Raw text content to analyze.
        db_path: Optional custom path to SQLite database.

    Returns:
        Populated InvestigationResult dataclass.
    """
    if text is None:
        return InvestigationResult(
            status=STATE_ERROR,
            matched=False,
            message="Input text cannot be None.",
            details="Invalid input provided to investigator.",
        )

    # Empty document has no fingerprint
    if not text.strip():
        return InvestigationResult(
            status=STATE_NO_FINGERPRINT,
            matched=False,
            fingerprint=None,
            extracted_text=text,
            cleaned_text="",
            message=MSG_NO_FINGERPRINT,
            details="Document contains empty text content.",
        )

    fp = fingerprint.decode_fingerprint(text)
    cleaned_text = fingerprint.remove_fingerprint(text)

    # STATE 3: No provenance fingerprint detected
    if not fp:
        return InvestigationResult(
            status=STATE_NO_FINGERPRINT,
            matched=False,
            fingerprint=None,
            recipient=None,
            document=None,
            extracted_text=text,
            cleaned_text=cleaned_text,
            message=MSG_NO_FINGERPRINT,
            details="No CanaryDocs zero-width Unicode steganographic watermark found in document.",
        )

    # Look up fingerprint in SQLite database
    fp_record = database.find_fingerprint(fp, db_path=db_path)

    # STATE 2: Fingerprint detected but source unknown
    if fp_record is None:
        return InvestigationResult(
            status=STATE_FINGERPRINT_UNKNOWN,
            matched=False,
            fingerprint=fp,
            recipient=None,
            document=None,
            extracted_text=text,
            cleaned_text=cleaned_text,
            message=MSG_FINGERPRINT_UNKNOWN,
            details=f"Valid CanaryDocs fingerprint token '{fp}' detected, but no matching registration exists in database.",
        )

    # Retrieve associated document and recipient
    document = database.get_document_by_id(fp_record.document_id, db_path=db_path)
    recipient = database.get_recipient_by_id(fp_record.recipient_id, db_path=db_path)

    if document is None or recipient is None:
        return InvestigationResult(
            status=STATE_FINGERPRINT_UNKNOWN,
            matched=False,
            fingerprint=fp,
            recipient=None,
            document=None,
            extracted_text=text,
            cleaned_text=cleaned_text,
            message=MSG_FINGERPRINT_UNKNOWN,
            details="Fingerprint record exists but associated document or recipient entity is missing from database.",
        )

    # STATE 1: Source identified
    return InvestigationResult(
        status=STATE_SOURCE_IDENTIFIED,
        matched=True,
        fingerprint=fp,
        recipient=recipient,
        document=document,
        extracted_text=text,
        cleaned_text=cleaned_text,
        message=MSG_SOURCE_IDENTIFIED,
        details=(
            f"Document '{document.document_name}' issued to "
            f"{recipient.name} ({recipient.center}) with UID {recipient.recipient_uid}."
        ),
    )


def investigate_document(
    file_path: Union[str, Path], db_path: Optional[Union[str, Path]] = None
) -> InvestigationResult:
    """Execute end-to-end leak investigation on an uploaded PDF or TXT file.

    Pipeline:
        1. Validate file existence and supported format (.pdf, .txt).
        2. Extract underlying Unicode text using document_parser.
        3. Scan and decode zero-width fingerprint.
        4. Query SQLite database for matching issuance record.
        5. Return structured InvestigationResult.

    Args:
        file_path: Path to the leaked document (PDF or TXT).
        db_path: Optional custom path to SQLite database.

    Returns:
        Structured InvestigationResult dataclass.
    """
    if not file_path:
        return InvestigationResult(
            status=STATE_ERROR,
            matched=False,
            message="File path cannot be empty.",
            details="No document path provided.",
        )

    path = Path(file_path).resolve()
    if not path.exists():
        return InvestigationResult(
            status=STATE_ERROR,
            matched=False,
            message=f"Document file not found: {file_path}",
            details="Target file does not exist on disk.",
        )

    if not path.is_file():
        return InvestigationResult(
            status=STATE_ERROR,
            matched=False,
            message=f"Path is not a regular file: {file_path}",
            details="Target path is a directory or invalid filesystem object.",
        )

    suffix = path.suffix.lower()
    if suffix not in (".pdf", ".txt"):
        return InvestigationResult(
            status=STATE_ERROR,
            matched=False,
            message=f"Unsupported document format '{suffix}'. Expected .pdf or .txt",
            details="Only PDF and TXT digital document formats are supported for steganographic extraction.",
        )

    try:
        extracted_text = document_parser.extract_document_text(path)
    except Exception as exc:
        return InvestigationResult(
            status=STATE_ERROR,
            matched=False,
            message=f"Text extraction failed: {exc}",
            details=str(exc),
        )

    return investigate_raw_text(extracted_text, db_path=db_path)
