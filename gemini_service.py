"""
gemini_service.py - AI-assisted forensic analysis powered by Google Gemini (google-genai).

Provides comparative forensic evaluation between canonical confidential documents
and leaked texts, analyzing leak severity, operational impact, content alterations,
possible paraphrasing, and redactions.

CRITICAL SCIENTIFIC & FORENSIC BOUNDARIES:
------------------------------------------
1. ADVISORY NATURE: Gemini's output is purely advisory and does not constitute
   legal or mathematical proof.
2. NO SOURCE ATTRIBUTION: Gemini MUST NEVER guess, speculate, or infer the identity
   of the leak source. Deterministic source attribution is derived strictly from
   zero-width steganography decoded by investigator.py and database lookup.
3. NO ACCUSATIONS: Never accuse individuals, fabricate intent, or invent evidence.
4. PARAPHRASING BOUNDARY: Do NOT claim that Gemini can prove an LLM performed paraphrasing.
   Use cautious phrasing such as "Possible paraphrasing detected" or "Semantic similarity observed."
5. ETHICAL RECOMMENDATIONS: Recommendations must focus on forensic evidence preservation,
   audit log inspection, and administrative review. Never recommend automated account
   deletion, credential revocation, or disciplinary action.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from typing import Any, Optional

from models import ForensicReport, InvestigationResult

# Configure local diagnostic logger writing to terminal (sys.stderr)
logger = logging.getLogger("canarydocs.gemini")
if not logger.handlers:
    _console_handler = logging.StreamHandler(sys.stderr)
    _console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(_console_handler)
logger.setLevel(logging.INFO)

try:
    from google import genai
    from google.genai import types
except ImportError:  # pragma: no cover
    genai = None  # type: ignore
    types = None  # type: ignore

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

SYSTEM_INSTRUCTION = """You are an expert digital document forensic analyst for CANARYDOCS.
Your task is to conduct an objective, AI-assisted comparative forensic evaluation between a canonical original document and a leaked document text.

CORE SEVERITY CLASSIFICATION DEFINITIONS:
- LOW:
  * Minor spelling mistakes or typographical errors
  * OCR noise, scanning artifacts, or text extraction irregularities
  * Minor formatting, spacing, or punctuation differences
  * Non-material wording or stylistic changes
  * No meaningful sensitive or confidential information exposure
- MEDIUM:
  * Noticeable substantive content changes or omissions
  * Limited redactions or selective withholding
  * Moderate semantic alterations or rewording
  * Limited or moderate sensitive information exposure
- HIGH:
  * Substantial sensitive or confidential content exposure
  * Major alteration or falsification of substantive content
  * Multiple sensitive sections exposed, removed, or materially changed
  * Significant operational, reputational, or institutional security impact
- CRITICAL:
  * Broad or near-complete exposure of highly classified or sensitive material
  * Major security compromise involving extensive sensitive information
  * Use CRITICAL ONLY when concrete evidence directly and unambiguously demonstrates extreme impact

CRITICAL FORENSIC, SAFETY, AND EVALUATION RULES:
1. ADVISORY & COMPARATIVE: Your analysis is strictly advisory. Never claim mathematical or legal proof.
2. NO SOURCE ATTRIBUTION: NEVER guess, speculate, or infer who leaked the document, their identity, role, or motivation. Source attribution in CANARYDOCS is handled strictly through deterministic cryptographic/steganographic database lookup.
3. NEVER INFER INTENT: Do not speculate about malice, intent, or culpability. State only observable facts.
4. EVIDENCE-BASED SEVERITY:
   * Do NOT assign HIGH or CRITICAL merely because the leaked document is substantially different from the canonical document.
   * Severity must reflect actual security impact and sensitive information exposure, NOT simply the count of textual differences.
   * Never fabricate or invent evidence not present in the supplied texts.
5. DISTINCT FINDINGS: Distinguish clearly and keep separate:
   * "content changes" (factual differences in text)
   * "sensitive information exposed" (what confidential data is leaked)
   * "possible redactions" (omitted or withheld parts)
   * "possible paraphrasing" (rewording or semantic drift)
   These are NOT automatically equivalent.
6. CAUTIOUS PARAPHRASING: Do NOT claim you can definitively prove an LLM performed paraphrasing. Use cautious wording such as "Possible paraphrasing detected."
7. OCR & TEXT QUALITY HANDLING:
   * Screenshots, raster images, and OCR do NOT preserve zero-width Unicode fingerprints.
   * If the leaked text is from OCR or exhibits scanning noise, OCR errors, or incomplete extraction, reduce evidence_quality to LOW or MEDIUM and reduce severity_confidence appropriately.
   * Do NOT treat OCR noise or extraction artifacts as intentional alterations or security severity.
8. UNRELATED DOCUMENTS:
   * If the canonical baseline and leaked document appear completely unrelated, explicitly indicate that they appear unrelated.
   * Assess the incident conservatively. Do NOT treat unrelatedness itself as evidence of a high-severity security breach.
9. ACTIONABLE RECOMMENDATIONS: Recommend forensic artifact preservation, log review, and distribution verification. Do NOT recommend automated punitive actions.

REQUIRED JSON OUTPUT FORMAT:
You MUST respond with a valid JSON object matching this exact schema:
{
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "severity_confidence": "LOW" | "MEDIUM" | "HIGH",
  "evidence_quality": "LOW" | "MEDIUM" | "HIGH",
  "severity_basis": [
    "Concrete evidence-based reason 1 from supplied texts",
    "Concrete evidence-based reason 2 from supplied texts"
  ],
  "impact": "Detailed assessment of operational and confidentiality impact.",
  "content_changes": [
    "Meaningful difference 1",
    "Meaningful difference 2"
  ],
  "possible_paraphrasing": {
    "detected": true | false,
    "explanation": "Cautious semantic analysis without asserting LLM proof."
  },
  "possible_redactions": {
    "detected": true | false,
    "explanation": "Identified omissions or withheld sections."
  },
  "recommendations": [
    "Actionable forensic recommendation 1",
    "Actionable forensic recommendation 2"
  ],
  "summary": "Concise executive summary of forensic findings."
}
"""


def sanitize_error_message(message: str, secret: Optional[str] = None) -> str:
    """Sanitize error messages before logging or UI display.

    Redacts Google API keys, authorization headers, bearer tokens, query parameters,
    and any passed active secrets so they are never leaked in terminal logs or UI.

    Args:
        message: Raw error message string or exception text.
        secret: Optional active API key/secret to explicitly scrub.

    Returns:
        Sanitized, safe error string.
    """
    if not message:
        return ""

    sanitized = str(message)

    # 1. Redact specific active secret if provided
    if secret and len(secret.strip()) >= 6:
        sanitized = sanitized.replace(secret.strip(), "[REDACTED_API_KEY]")

    # 2. Redact environment GEMINI_API_KEY if present
    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if env_key and len(env_key) >= 6:
        sanitized = sanitized.replace(env_key, "[REDACTED_API_KEY]")

    # 3. Redact Google AI Studio API key pattern (AIza...)
    sanitized = re.sub(r"AIza[0-9A-Za-z-_]{30,}", "[REDACTED_API_KEY]", sanitized)

    # 4. Redact URL query parameters containing keys (?key=..., &key=...)
    sanitized = re.sub(r"([?&]key=)[^&\s'\"]+", r"\g<1>[REDACTED_API_KEY]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(key=)[^&\s'\"]+", r"\g<1>[REDACTED_API_KEY]", sanitized, flags=re.IGNORECASE)

    # 5. Redact Bearer tokens
    sanitized = re.sub(r"(Bearer\s+)[^\s,;'\"]+", r"\g<1>[REDACTED_TOKEN]", sanitized, flags=re.IGNORECASE)

    # 6. Redact x-goog-api-key headers
    sanitized = re.sub(r"(x-goog-api-key\s*[:=]\s*)[^\s,;'\"]+", r"\g<1>[REDACTED_API_KEY]", sanitized, flags=re.IGNORECASE)

    # 7. Redact generic Authorization headers
    sanitized = re.sub(r"(authorization\s*[:=]\s*)[^\s,;'\"]+", r"\g<1>[REDACTED_AUTH]", sanitized, flags=re.IGNORECASE)

    return sanitized


def get_gemini_client(api_key: Optional[str] = None) -> Any:
    """Initialize and return a Google GenAI client instance.

    Retrieves the API key strictly from the GEMINI_API_KEY environment variable
    or the passed parameter. Never hardcodes, logs, or prints the API key.

    Args:
        api_key: Optional Gemini API key. Defaults to GEMINI_API_KEY environment variable.

    Returns:
        Configured genai.Client instance.

    Raises:
        ValueError: If no API key is provided or found in environment.
        RuntimeError: If google-genai SDK is not installed.
    """
    if genai is None:
        raise RuntimeError("google-genai SDK is not installed.")

    resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
    if not resolved_key or not resolved_key.strip():
        raise ValueError(
            "GEMINI_API_KEY is not set. Please configure the GEMINI_API_KEY environment variable."
        )

    return genai.Client(api_key=resolved_key.strip())


def build_incident_metadata(
    investigation_result: InvestigationResult,
) -> dict[str, Any]:
    """Convert an InvestigationResult into contextual metadata for forensic analysis.

    Only non-sensitive, relevant forensic context is extracted.

    Args:
        investigation_result: InvestigationResult from investigator.py.

    Returns:
        Dictionary of metadata fields.
    """
    metadata: dict[str, Any] = {
        "investigation_status": investigation_result.status,
        "matched": investigation_result.matched,
    }
    if investigation_result.fingerprint:
        metadata["fingerprint"] = investigation_result.fingerprint
    if investigation_result.document:
        metadata["document_name"] = investigation_result.document.document_name
        metadata["document_type"] = investigation_result.document.document_type
    if investigation_result.recipient:
        metadata["recipient_name"] = investigation_result.recipient.name
        metadata["recipient_uid"] = investigation_result.recipient.recipient_uid
        metadata["center"] = investigation_result.recipient.center

    return metadata


def parse_forensic_response(raw_text: str) -> ForensicReport:
    """Parse and validate JSON model output into a structured ForensicReport.

    Handles raw JSON, markdown-wrapped JSON (```json ... ```), and malformed output.

    Args:
        raw_text: Model response string.

    Returns:
        Validated ForensicReport dataclass.
    """
    cleaned = raw_text.strip()

    # Strip markdown codeblocks if present
    codeblock_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
    if codeblock_match:
        cleaned = codeblock_match.group(1).strip()

    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            # Validate and normalize severity
            raw_severity = str(data.get("severity", "MEDIUM")).upper()
            severity = (
                raw_severity
                if raw_severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
                else "MEDIUM"
            )

            # Validate and normalize severity_confidence
            raw_conf = str(data.get("severity_confidence", "MEDIUM")).upper()
            severity_confidence = (
                raw_conf
                if raw_conf in ("LOW", "MEDIUM", "HIGH")
                else "MEDIUM"
            )

            # Validate and normalize evidence_quality
            raw_qual = str(data.get("evidence_quality", "MEDIUM")).upper()
            evidence_quality = (
                raw_qual
                if raw_qual in ("LOW", "MEDIUM", "HIGH")
                else "MEDIUM"
            )

            # Validate and extract severity_basis (list of strings)
            raw_basis = data.get("severity_basis", [])
            if isinstance(raw_basis, list):
                severity_basis = [str(item).strip() for item in raw_basis if str(item).strip()]
            elif isinstance(raw_basis, str) and raw_basis.strip():
                severity_basis = [raw_basis.strip()]
            else:
                severity_basis = []

            # Extract impact
            impact = str(
                data.get(
                    "impact", "Forensic analysis completed with standard advisory findings."
                )
            )

            # Extract content_changes
            raw_changes = data.get("content_changes", [])
            content_changes = (
                raw_changes
                if isinstance(raw_changes, list)
                else [str(raw_changes)]
            )

            # Extract possible_paraphrasing
            raw_para = data.get("possible_paraphrasing", {})
            if isinstance(raw_para, dict):
                possible_paraphrasing = {
                    "detected": bool(raw_para.get("detected", False)),
                    "explanation": str(
                        raw_para.get("explanation", "No paraphrasing detected.")
                    ),
                }
            elif isinstance(raw_para, list):
                possible_paraphrasing = {
                    "detected": len(raw_para) > 0,
                    "explanation": "; ".join(str(p) for p in raw_para),
                }
            else:
                possible_paraphrasing = {
                    "detected": bool(raw_para),
                    "explanation": str(raw_para),
                }

            # Extract possible_redactions
            raw_redact = data.get("possible_redactions", {})
            if isinstance(raw_redact, dict):
                possible_redactions = {
                    "detected": bool(raw_redact.get("detected", False)),
                    "explanation": str(
                        raw_redact.get("explanation", "No redactions detected.")
                    ),
                }
            elif isinstance(raw_redact, list):
                possible_redactions = {
                    "detected": len(raw_redact) > 0,
                    "explanation": "; ".join(str(r) for r in raw_redact),
                }
            else:
                possible_redactions = {
                    "detected": bool(raw_redact),
                    "explanation": str(raw_redact),
                }

            # Extract recommendations
            raw_recs = data.get("recommendations", [])
            recommendations = (
                raw_recs if isinstance(raw_recs, list) else [str(raw_recs)]
            )

            # Extract summary
            summary = str(data.get("summary", impact[:150]))

            return ForensicReport(
                severity=severity,
                impact=impact,
                content_changes=content_changes,
                possible_paraphrasing=possible_paraphrasing,
                possible_redactions=possible_redactions,
                recommendations=recommendations,
                summary=summary,
                raw_analysis=raw_text,
                severity_confidence=severity_confidence,
                evidence_quality=evidence_quality,
                severity_basis=severity_basis,
            )

    except Exception:
        pass

    # Safe fallback if JSON parsing fails entirely
    return ForensicReport(
        severity="MEDIUM",
        impact="Automated structured parsing failed; manual forensic evaluation of raw response required.",
        content_changes=["Unstructured model response returned."],
        possible_paraphrasing={
            "detected": False,
            "explanation": "Unable to verify paraphrasing due to unstructured model response.",
        },
        possible_redactions={
            "detected": False,
            "explanation": "Unable to verify redactions due to unstructured model response.",
        },
        recommendations=[
            "Preserve original leaked document artifact.",
            "Conduct manual line-by-line textual comparison.",
            "Verify deterministic steganographic attribution records.",
        ],
        summary="Model returned an unstructured forensic evaluation.",
        raw_analysis=raw_text,
        severity_confidence="LOW",
        evidence_quality="LOW",
        severity_basis=[
            "Automated structured parsing failed; manual forensic evaluation of raw response required."
        ],
    )



def analyze_incident(
    original_text: str,
    leaked_text: str,
    metadata: Optional[dict[str, Any]] = None,
    client: Optional[Any] = None,
    api_key: Optional[str] = None,
) -> ForensicReport:
    """Perform comparative forensic analysis using Google Gemini.

    Compares the original registered document text against the leaked document text.
    Assesses:
    - severity: Qualitative rating ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
    - impact: Potential operational, intelligence, or confidentiality fallout.
    - content_changes: Key differences, omissions, additions, or edits.
    - possible_paraphrasing: Semantic analysis of rewritten or altered text.
      (Note: Highlights likely rewording; does not claim proof of LLM generation).
    - possible_redactions: Detected blacked-out or omitted sensitive details.
    - recommendations: Practical incident response and mitigation measures.

    Args:
        original_text: Canonical text of the confidential document from database.
        leaked_text: Cleaned text extracted from the leaked document.
        metadata: Contextual data (document name, type, issuance details).
        client: Optional injected genai.Client instance (useful for testing).
        api_key: Optional explicit Gemini API key. Defaults to GEMINI_API_KEY environment variable.

    Returns:
        Structured ForensicReport dataclass.

    Raises:
        ValueError: If GEMINI_API_KEY is missing from environment.
    """
    # Handle empty input cases cleanly without unnecessary API calls
    if not original_text or not original_text.strip():
        return ForensicReport(
            severity="LOW",
            impact="Unable to assess impact: original canonical document text is empty.",
            content_changes=["Original document text was empty."],
            possible_paraphrasing={
                "detected": False,
                "explanation": "Comparison impossible with empty original text.",
            },
            possible_redactions={
                "detected": False,
                "explanation": "Comparison impossible with empty original text.",
            },
            recommendations=[
                "Verify canonical document registration in database.",
                "Ensure original document text was correctly ingested.",
            ],
            summary="Forensic analysis aborted: original document text is empty.",
            raw_analysis="Original text is empty.",
            severity_confidence="HIGH",
            evidence_quality="LOW",
            severity_basis=["Original canonical document text is empty."],
        )

    if not leaked_text or not leaked_text.strip():
        return ForensicReport(
            severity="LOW",
            impact="Unable to assess impact: leaked document text is empty.",
            content_changes=["Leaked document text was empty."],
            possible_paraphrasing={
                "detected": False,
                "explanation": "No leaked text detected for comparison.",
            },
            possible_redactions={
                "detected": True,
                "explanation": "Entire document content appears redacted, blank, or unextracted.",
            },
            recommendations=[
                "Verify file integrity and extraction pipeline for the leaked document.",
                "Inspect the physical artifact for complete redaction or image-only pages.",
            ],
            summary="Forensic analysis aborted: leaked document text is empty.",
            raw_analysis="Leaked text is empty.",
            severity_confidence="HIGH",
            evidence_quality="LOW",
            severity_basis=["Leaked document text is empty or unextracted."],
        )


    # Initialize Gemini client if not injected
    if client is None:
        client = get_gemini_client(api_key=api_key)

    model_name = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)

    # Construct the forensic comparison prompt
    meta_desc = ""
    if metadata:
        meta_items = [f"- {k}: {v}" for k, v in metadata.items() if v is not None]
        if meta_items:
            meta_desc = "INCIDENT METADATA:\n" + "\n".join(meta_items) + "\n\n"

    user_prompt = (
        f"{meta_desc}"
        f"=== ORIGINAL CANONICAL DOCUMENT TEXT ===\n"
        f"{original_text.strip()}\n\n"
        f"=== LEAKED DOCUMENT TEXT ===\n"
        f"{leaked_text.strip()}\n\n"
        f"Provide your structured comparative forensic analysis in JSON format."
    )

    try:
        # Call modern Google GenAI SDK
        if types is not None:
            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                temperature=0.2,
            )
            response = client.models.generate_content(
                model=model_name,
                contents=user_prompt,
                config=config,
            )
        else:  # pragma: no cover
            response = client.models.generate_content(
                model=model_name,
                contents=f"{SYSTEM_INSTRUCTION}\n\n{user_prompt}",
            )

        raw_output = response.text or ""
        return parse_forensic_response(raw_output)

    except Exception as exc:
        exc_type = type(exc).__name__
        err_str = str(exc)
        err_msg = sanitize_error_message(err_str, secret=api_key)

        # Redact raw document or leaked text contents if reflected in the error
        if original_text and len(original_text.strip()) > 10:
            err_msg = err_msg.replace(original_text.strip(), "[REDACTED_DOCUMENT_TEXT]")
        if leaked_text and len(leaked_text.strip()) > 10:
            err_msg = err_msg.replace(leaked_text.strip(), "[REDACTED_LEAKED_TEXT]")

        # Log actual exception type and sanitized message to terminal for local debugging
        logger.error("[CANARYDOCS - GEMINI ERROR] %s: %s", exc_type, err_msg)

        if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str.upper() or "quota" in err_str.lower():
            friendly_summary = "Gemini API rate limit or quota exceeded (429). Please wait a moment and retry."
        elif "401" in err_str or "403" in err_str or "API_KEY_INVALID" in err_str.upper() or "PERMISSION_DENIED" in err_str.upper():
            friendly_summary = "Invalid or unauthorized Gemini API key. Please verify your API key in Google AI Studio."
        elif "404" in err_str or "NOT_FOUND" in err_str.upper():
            friendly_summary = f"Gemini model not found (404). Please verify GEMINI_MODEL setting (current: '{model_name}')."
        else:
            friendly_summary = "Gemini API request failed. Manual forensic verification required."

        # Gracefully handle API or network errors without crashing
        return ForensicReport(
            severity="MEDIUM",
            impact=f"Automated AI forensic evaluation encountered an error: {err_msg}",
            content_changes=["Analysis could not complete due to API error."],
            possible_paraphrasing={
                "detected": False,
                "explanation": "Analysis unavailable due to service error.",
            },
            possible_redactions={
                "detected": False,
                "explanation": "Analysis unavailable due to service error.",
            },
            recommendations=[
                "Preserve all forensic artifacts and investigate deterministically.",
                "Verify Gemini API connectivity, quotas, and network status.",
                "Perform manual diffing between original and leaked texts.",
            ],
            summary=friendly_summary,
            raw_analysis=err_msg,
            severity_confidence="LOW",
            evidence_quality="LOW",
            severity_basis=[f"Automated AI evaluation encountered a service error: {friendly_summary}"],
        )

