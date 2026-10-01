"""
models.py - Shared domain models and dataclasses for CANARYDOCS.

Defines the core data structures used across document generation,
fingerprint encoding/decoding, database persistence, leak investigation,
and Gemini forensic analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Union


@dataclass
class Recipient:
    """Represents an individual or entity receiving a canary document.

    Attributes:
        recipient_uid: Unique identifier (e.g., clearance code or badge ID).
        name: Full name of recipient.
        center: Department, division, or organizational center.
        id: Primary key in the database (None if not yet persisted).
    """

    recipient_uid: str
    name: str
    center: str
    id: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert recipient model to a dictionary representation."""
        return {
            "id": self.id,
            "recipient_uid": self.recipient_uid,
            "name": self.name,
            "center": self.center,
        }


@dataclass
class Document:
    """Represents a canonical confidential document tracked in the system.

    Attributes:
        document_name: Title or filename of the document.
        document_type: Category (e.g., 'OPERATIONAL_BRIEF', 'FINANCIAL_PROJECTION').
        original_text: Unmodified canonical text of the document.
        id: Primary key in the database (None if not yet persisted).
        created_at: ISO timestamp of document registration.
    """

    document_name: str
    document_type: str
    original_text: str
    id: Optional[int] = None
    created_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert document model to a dictionary representation."""
        return {
            "id": self.id,
            "document_name": self.document_name,
            "document_type": self.document_type,
            "original_text": self.original_text,
            "created_at": self.created_at,
        }


@dataclass
class FingerprintRecord:
    """Maps a recipient to an issued document via a unique fingerprint hash.

    Attributes:
        document_id: Foreign key reference to documents table.
        recipient_id: Foreign key reference to recipients table.
        fingerprint: Unique fingerprint payload (e.g. hex digest or token).
        id: Primary key in the database (None if not yet persisted).
        issued_at: ISO timestamp of issuance.
    """

    document_id: int
    recipient_id: int
    fingerprint: str
    id: Optional[int] = None
    issued_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert fingerprint record to a dictionary representation."""
        return {
            "id": self.id,
            "document_id": self.document_id,
            "recipient_id": self.recipient_id,
            "fingerprint": self.fingerprint,
            "issued_at": self.issued_at,
        }


@dataclass
class InvestigationResult:
    """Result of analyzing a leaked or submitted document.

    Attributes:
        status: Forensic investigation status
            ('SOURCE IDENTIFIED', 'FINGERPRINT DETECTED — SOURCE UNKNOWN',
             'NO PROVENANCE FINGERPRINT DETECTED', 'ERROR').
        matched: Boolean flag indicating if recipient source was identified.
        fingerprint: Extracted fingerprint string, if detected.
        recipient: Associated Recipient record if fingerprint resolved.
        document: Associated Document record if fingerprint resolved.
        extracted_text: Raw text extracted from the investigated file.
        cleaned_text: Extracted text with all zero-width characters stripped.
        message: Descriptive summary message for user / UI.
        details: Diagnostic or contextual messages regarding the investigation.
    """

    status: str
    matched: bool = False
    fingerprint: Optional[str] = None
    recipient: Optional[Recipient] = None
    document: Optional[Document] = None
    extracted_text: str = ""
    cleaned_text: str = ""
    message: str = ""
    details: Optional[str] = None

    @property
    def is_match(self) -> bool:
        """Convenience property indicating whether an identified leak culprit was found."""
        return self.matched or (self.status in ("MATCH_FOUND", "SOURCE IDENTIFIED") and self.recipient is not None)

    def to_dict(self) -> dict[str, Any]:
        """Convert investigation result to a serializable dictionary."""
        return {
            "status": self.status,
            "matched": self.matched,
            "fingerprint": self.fingerprint,
            "recipient": self.recipient.to_dict() if self.recipient else None,
            "document": self.document.to_dict() if self.document else None,
            "extracted_text_preview": (
                self.extracted_text[:200] + "..." if len(self.extracted_text) > 200 else self.extracted_text
            ),
            "is_match": self.is_match,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ForensicReport:
    """AI-assisted forensic comparative analysis produced by Gemini.

    Attributes:
        severity: Assessed breach severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        impact: Assessment of operational, reputational, or security consequences.
        content_changes: List or explanation of alterations between original and leaked texts.
        possible_paraphrasing: Semantic similarity assessment (dict, list, or string).
        possible_redactions: Sections or details detected as omitted or censored.
        recommendations: Actionable incident response and mitigation steps.
        summary: Concise executive summary of forensic findings.
        raw_analysis: Complete unparsed Gemini model response text.
        severity_confidence: Confidence level in severity rating ('LOW', 'MEDIUM', 'HIGH').
        evidence_quality: Quality and completeness of evidence ('LOW', 'MEDIUM', 'HIGH').
        severity_basis: Concrete evidence-based reasons supporting the severity score.
    """

    severity: str
    impact: str
    content_changes: list[str] = field(default_factory=list)
    possible_paraphrasing: Any = field(default_factory=dict)
    possible_redactions: Any = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    summary: str = ""
    raw_analysis: str = ""
    severity_confidence: str = "MEDIUM"
    evidence_quality: str = "MEDIUM"
    severity_basis: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert forensic report to a dictionary representation."""
        return {
            "severity": self.severity,
            "severity_confidence": self.severity_confidence,
            "evidence_quality": self.evidence_quality,
            "severity_basis": self.severity_basis,
            "impact": self.impact,
            "content_changes": self.content_changes,
            "possible_paraphrasing": self.possible_paraphrasing,
            "possible_redactions": self.possible_redactions,
            "recommendations": self.recommendations,
            "summary": self.summary,
            "raw_analysis": self.raw_analysis,
        }

