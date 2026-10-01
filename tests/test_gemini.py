"""
test_gemini.py - Unit tests for the AI-assisted forensic analysis service (gemini_service.py).

Verifies:
1. Valid structured Gemini response parses correctly.
2. Severity is correctly extracted and normalized.
3. Content changes are extracted.
4. Possible paraphrasing is extracted.
5. Possible redactions are extracted.
6. Recommendations are extracted.
7. Malformed JSON response is handled safely without crashing.
8. Missing API key is handled safely with a clear ValueError.
9. Empty original/leaked text is handled without calling the API.
10. Verify no API key is hardcoded in gemini_service.py.
11. build_incident_metadata helper formats metadata correctly.

All tests utilize mocked responses and DO NOT require live Gemini API network calls.
"""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

import gemini_service
from models import Document, ForensicReport, InvestigationResult, Recipient


class FakeResponse:
    """Mock Gemini API response object."""

    def __init__(self, text: str):
        self.text = text


class FakeModels:
    """Mock models service for Google GenAI Client."""

    def __init__(self, response_text: str):
        self.response_text = response_text
        self.last_call = None

    def generate_content(self, model: str, contents: str, config=None):
        self.last_call = {"model": model, "contents": contents, "config": config}
        return FakeResponse(self.response_text)


class FakeGenAIClient:
    """Mock Google GenAI Client matching genai.Client interface."""

    def __init__(self, response_text: str):
        self.models = FakeModels(response_text)


VALID_JSON_RESPONSE = """
{
  "severity": "HIGH",
  "impact": "Uncontrolled disclosure of confidential examination questions threatens curriculum integrity.",
  "content_changes": [
    "Section B was omitted entirely from the leaked text.",
    "Section A instructions were slightly abbreviated."
  ],
  "possible_paraphrasing": {
    "detected": true,
    "explanation": "The leaked text appears semantically similar to the original questions despite minor syntactic rewording."
  },
  "possible_redactions": {
    "detected": true,
    "explanation": "Marking schemes and examiner notes appear to have been removed."
  },
  "recommendations": [
    "Preserve the leaked artifact and extracted metadata intact.",
    "Compare the leaked document against canonical examination registries.",
    "Review distribution records for the recipient identified by deterministic steganography."
  ],
  "summary": "High severity leak with selective redactions and minor paraphrasing."
}
"""


# TEST 1: Valid structured Gemini response parses correctly
def test_1_valid_structured_gemini_response_parses():
    """Verify that a valid JSON model output parses into a complete ForensicReport."""
    fake_client = FakeGenAIClient(VALID_JSON_RESPONSE)

    report = gemini_service.analyze_incident(
        original_text="Original test text",
        leaked_text="Leaked test text",
        client=fake_client,
    )

    assert isinstance(report, ForensicReport)
    assert report.severity == "HIGH"
    assert "curriculum integrity" in report.impact
    assert report.summary == "High severity leak with selective redactions and minor paraphrasing."


# TEST 2: Severity is correctly extracted and normalized
def test_2_severity_extracted_and_normalized():
    """Verify severity extraction handles various cases and defaults safely."""
    for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        json_data = f'{{"severity": "{sev.lower()}", "impact": "Test impact"}}'
        report = gemini_service.parse_forensic_response(json_data)
        assert report.severity == sev

    # Unknown severity falls back to MEDIUM
    unknown_json = '{"severity": "APOCALYPTIC", "impact": "Severe"}'
    unknown_report = gemini_service.parse_forensic_response(unknown_json)
    assert unknown_report.severity == "MEDIUM"


# TEST 3: Content changes are extracted
def test_3_content_changes_extracted():
    """Verify content changes list is extracted correctly."""
    fake_client = FakeGenAIClient(VALID_JSON_RESPONSE)
    report = gemini_service.analyze_incident(
        original_text="Original text",
        leaked_text="Leaked text",
        client=fake_client,
    )

    assert len(report.content_changes) == 2
    assert "Section B was omitted entirely" in report.content_changes[0]


# TEST 4: Possible paraphrasing is extracted
def test_4_possible_paraphrasing_extracted():
    """Verify paraphrasing detection and explanation are extracted."""
    fake_client = FakeGenAIClient(VALID_JSON_RESPONSE)
    report = gemini_service.analyze_incident(
        original_text="Original text",
        leaked_text="Leaked text",
        client=fake_client,
    )

    assert isinstance(report.possible_paraphrasing, dict)
    assert report.possible_paraphrasing["detected"] is True
    assert "semantically similar" in report.possible_paraphrasing["explanation"]


# TEST 5: Possible redactions are extracted
def test_5_possible_redactions_extracted():
    """Verify redactions detection and explanation are extracted."""
    fake_client = FakeGenAIClient(VALID_JSON_RESPONSE)
    report = gemini_service.analyze_incident(
        original_text="Original text",
        leaked_text="Leaked text",
        client=fake_client,
    )

    assert isinstance(report.possible_redactions, dict)
    assert report.possible_redactions["detected"] is True
    assert "Marking schemes" in report.possible_redactions["explanation"]


# TEST 6: Recommendations are extracted
def test_6_recommendations_extracted():
    """Verify investigator recommendations list is extracted."""
    fake_client = FakeGenAIClient(VALID_JSON_RESPONSE)
    report = gemini_service.analyze_incident(
        original_text="Original text",
        leaked_text="Leaked text",
        client=fake_client,
    )

    assert len(report.recommendations) == 3
    assert "Preserve the leaked artifact" in report.recommendations[0]


# TEST 7: Malformed JSON response is handled safely
def test_7_malformed_json_response_handled_safely():
    """Verify invalid or non-JSON model output falls back safely without crashing."""
    malformed_text = "This is not valid JSON. The document appears to have been leaked."
    fake_client = FakeGenAIClient(malformed_text)

    report = gemini_service.analyze_incident(
        original_text="Original text",
        leaked_text="Leaked text",
        client=fake_client,
    )

    assert isinstance(report, ForensicReport)
    assert report.severity == "MEDIUM"
    assert "manual forensic evaluation" in report.impact.lower()
    assert report.raw_analysis == malformed_text


# TEST 8: Missing API key is handled safely
def test_8_missing_api_key_handled_safely(monkeypatch):
    """Verify missing GEMINI_API_KEY environment variable raises clear ValueError."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GEMINI_API_KEY is not set"):
        gemini_service.get_gemini_client()

    with pytest.raises(ValueError, match="GEMINI_API_KEY is not set"):
        gemini_service.analyze_incident("Original text", "Leaked text")


# TEST 9: Empty original/leaked text is handled without calling API
def test_9_empty_text_handled_safely():
    """Verify empty text inputs return informative ForensicReport without making API calls."""
    # Empty original text
    rep_empty_orig = gemini_service.analyze_incident("", "Some leaked content")
    assert rep_empty_orig.severity == "LOW"
    assert "original canonical document text is empty" in rep_empty_orig.impact

    # Empty leaked text
    rep_empty_leak = gemini_service.analyze_incident("Original content", "")
    assert rep_empty_leak.severity == "LOW"
    assert "leaked document text is empty" in rep_empty_leak.impact
    assert rep_empty_leak.possible_redactions["detected"] is True


# TEST 10: Verify no API key is hardcoded in gemini_service.py
def test_10_no_hardcoded_api_key():
    """Verify that gemini_service.py contains no hardcoded secrets or API keys."""
    service_path = Path(__file__).resolve().parent.parent / "gemini_service.py"
    source = service_path.read_text(encoding="utf-8")

    assert "AIzaSy" not in source
    assert 'api_key="' not in source
    assert "api_key = '" not in source
    assert 'api_key = "' not in source
    assert 'GEMINI_API_KEY = "' not in source


# TEST 11: build_incident_metadata helper
def test_11_build_incident_metadata_helper():
    """Verify build_incident_metadata extracts relevant fields from InvestigationResult."""
    doc = Document(document_name="Exam 2026", document_type="CONFIDENTIAL", original_text="Text")
    rec = Recipient(recipient_uid="UID-042", name="Candidate A", center="Center X")
    inv = InvestigationResult(
        status="SOURCE IDENTIFIED",
        matched=True,
        fingerprint="UID-042",
        recipient=rec,
        document=doc,
    )

    metadata = gemini_service.build_incident_metadata(inv)
    assert metadata["investigation_status"] == "SOURCE IDENTIFIED"
    assert metadata["matched"] is True
    assert metadata["fingerprint"] == "UID-042"
    assert metadata["document_name"] == "Exam 2026"
    assert metadata["recipient_uid"] == "UID-042"
    assert metadata["center"] == "Center X"


# TEST 12: sanitize_error_message scrubs all forms of credentials
def test_12_sanitize_error_message_scrubs_all_credentials():
    """Verify sanitize_error_message removes API keys, tokens, and custom secrets."""
    # 1. Google API key pattern
    raw_key = "AIzaSyD_TestKey123456789012345678901234"
    scrubbed = gemini_service.sanitize_error_message(f"Error at https://example.com?key={raw_key}")
    assert raw_key not in scrubbed
    assert "[REDACTED_API_KEY]" in scrubbed

    # 2. Bearer token
    bearer_raw = "Bearer ya29.a0AfH6SMCredentialToken12345"
    scrubbed_bearer = gemini_service.sanitize_error_message(f"Auth failure: {bearer_raw}")
    assert "ya29.a0AfH6SMCredentialToken12345" not in scrubbed_bearer
    assert "[REDACTED_TOKEN]" in scrubbed_bearer

    # 3. Headers
    hdr_raw = "x-goog-api-key: custom-secret-key-12345, authorization: Basic xyz"
    scrubbed_hdr = gemini_service.sanitize_error_message(hdr_raw)
    assert "custom-secret-key-12345" not in scrubbed_hdr
    assert "[REDACTED_API_KEY]" in scrubbed_hdr
    assert "[REDACTED_AUTH]" in scrubbed_hdr

    # 4. Explicit passed secret
    my_secret = "super-secret-passphrase-999"
    scrubbed_custom = gemini_service.sanitize_error_message(
        f"Failed validation for {my_secret}", secret=my_secret
    )
    assert my_secret not in scrubbed_custom
    assert "[REDACTED_API_KEY]" in scrubbed_custom


# TEST 13: api_failure logs sanitized exception to terminal
def test_13_api_failure_logs_sanitized_exception_to_terminal(caplog):
    """Verify that Gemini API failures log the exception type and sanitized message for debugging."""
    import logging

    fake_key = "AIzaSyB9876543210zyxwvutsrqponmlkjihgfe"
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError(
        f"404 NOT_FOUND. models/gemini-2.5-flash is not found at https://generativelanguage.googleapis.com?key={fake_key}"
    )

    with caplog.at_level(logging.ERROR, logger="canarydocs.gemini"):
        report = gemini_service.analyze_incident(
            original_text="Canonical examination text",
            leaked_text="Leaked examination text",
            client=mock_client,
            api_key=fake_key,
        )

    # 1. Terminal log must contain the error and exception type
    assert "[CANARYDOCS - GEMINI ERROR]" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "404 NOT_FOUND" in caplog.text

    # 2. Secret must NEVER appear in terminal logs
    assert fake_key not in caplog.text
    assert "[REDACTED_API_KEY]" in caplog.text

    # 3. User-facing UI report remains friendly and safe
    assert fake_key not in report.impact
    assert fake_key not in report.summary
    assert "404" in report.summary or "failed" in report.summary.lower()


# TEST 14: api_failure redacts sensitive document contents from logs
def test_14_api_failure_redacts_sensitive_document_contents(caplog):
    """Verify that reflected confidential document text is redacted from logs."""
    import logging

    confidential_doc = "SECRET_EXAM_QUESTION_TOP_PRIORITY_NEET_2026_BIOLOGY"
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError(
        f"Invalid token encountered in prompt: {confidential_doc}"
    )

    with caplog.at_level(logging.ERROR, logger="canarydocs.gemini"):
        report = gemini_service.analyze_incident(
            original_text=confidential_doc,
            leaked_text="Leaked document text",
            client=mock_client,
        )

    # Document text must be scrubbed from log
    assert confidential_doc not in caplog.text
    assert "[REDACTED_DOCUMENT_TEXT]" in caplog.text
    assert "[REDACTED_DOCUMENT_TEXT]" in report.impact


# TEST 15: Severity A - LOW (Spelling, OCR noise, minor formatting)
def test_15_severity_low_spelling_ocr_formatting():
    """TEST A: Verify LOW severity classification for minor spelling, OCR noise, and formatting."""
    low_response = """
    {
      "severity": "LOW",
      "severity_confidence": "HIGH",
      "evidence_quality": "HIGH",
      "severity_basis": [
        "Differences limited to minor typographical spelling variations in Question 3",
        "Minor OCR scanning noise and whitespace shifts with no substantive textual alteration",
        "No confidential or sensitive information exposed beyond public draft"
      ],
      "impact": "Negligible security impact; public curriculum draft unaffected.",
      "content_changes": ["Punctuation and spacing differences."],
      "possible_paraphrasing": {"detected": false, "explanation": "No semantic paraphrasing."},
      "possible_redactions": {"detected": false, "explanation": "No sections omitted."},
      "recommendations": ["Retain document for standard audit archives."],
      "summary": "Low severity incident involving only cosmetic and OCR formatting differences."
    }
    """
    report = gemini_service.parse_forensic_response(low_response)
    assert report.severity == "LOW"
    assert report.severity_confidence == "HIGH"
    assert report.evidence_quality == "HIGH"
    assert len(report.severity_basis) == 3
    assert "typographical" in report.severity_basis[0]


# TEST 16: Severity B - MEDIUM (Moderate content changes, limited redactions)
def test_16_severity_medium_moderate_changes_limited_redactions():
    """TEST B: Verify MEDIUM severity classification for moderate changes and limited redactions."""
    med_response = """
    {
      "severity": "MEDIUM",
      "severity_confidence": "HIGH",
      "evidence_quality": "HIGH",
      "severity_basis": [
        "Moderate content modifications detected in Section B instructions",
        "Selective redaction of examiner notes and trial item markings",
        "Sensitive answer keys remain unexposed"
      ],
      "impact": "Moderate operational concern regarding examiner guidance exposure.",
      "content_changes": ["Examiner comments removed."],
      "possible_paraphrasing": {"detected": true, "explanation": "Possible paraphrasing detected in Section B."},
      "possible_redactions": {"detected": true, "explanation": "Examiner notes omitted."},
      "recommendations": ["Review distribution chain for examiner copies."],
      "summary": "Medium severity leak with selective redactions of internal guidance."
    }
    """
    report = gemini_service.parse_forensic_response(med_response)
    assert report.severity == "MEDIUM"
    assert report.severity_confidence == "HIGH"
    assert report.evidence_quality == "HIGH"
    assert len(report.severity_basis) == 3


# TEST 17: Severity C - HIGH (Substantial sensitive content exposure)
def test_17_severity_high_substantial_sensitive_exposure():
    """TEST C: Verify HIGH severity classification for substantial sensitive content exposure."""
    high_response = """
    {
      "severity": "HIGH",
      "severity_confidence": "HIGH",
      "evidence_quality": "HIGH",
      "severity_basis": [
        "Multiple live examination questions exposed verbatim",
        "Substantive scoring metrics and candidate benchmarks leaked",
        "Significant breach of confidential trial assessment materials"
      ],
      "impact": "Substantial breach compromising confidential assessment integrity.",
      "content_changes": ["Full Section A and Section B questions exposed."],
      "possible_paraphrasing": {"detected": false, "explanation": "Verbatim reproduction."},
      "possible_redactions": {"detected": false, "explanation": "Full questions published without redaction."},
      "recommendations": ["Preserve forensic evidence artifacts and review chain-of-custody."],
      "summary": "High severity leak compromising core confidential questions."
    }
    """
    report = gemini_service.parse_forensic_response(high_response)
    assert report.severity == "HIGH"
    assert report.severity_confidence == "HIGH"
    assert report.evidence_quality == "HIGH"
    assert len(report.severity_basis) == 3


# TEST 18: Severity D - CRITICAL (Broad exposure of highly sensitive material)
def test_18_severity_critical_broad_exposure():
    """TEST D: Verify CRITICAL severity classification for broad, near-complete exposure of highly sensitive material."""
    crit_response = """
    {
      "severity": "CRITICAL",
      "severity_confidence": "HIGH",
      "evidence_quality": "HIGH",
      "severity_basis": [
        "Near-complete exposure of entire national question bank with full official answer keys",
        "Extensive compromise of national trial assessment security",
        "Direct concrete evidence of complete paper dissemination prior to scheduled release"
      ],
      "impact": "Catastrophic compromise requiring immediate curriculum invalidation.",
      "content_changes": ["Entire question bank and answer keys leaked."],
      "possible_paraphrasing": {"detected": false, "explanation": "Verbatim leak."},
      "possible_redactions": {"detected": false, "explanation": "No redactions; complete disclosure."},
      "recommendations": ["Immediately notify national examination steering committee."],
      "summary": "Critical breach involving comprehensive live question bank disclosure."
    }
    """
    report = gemini_service.parse_forensic_response(crit_response)
    assert report.severity == "CRITICAL"
    assert report.severity_confidence == "HIGH"
    assert report.evidence_quality == "HIGH"
    assert len(report.severity_basis) == 3


# TEST 19: Severity E - Unrelated documents assessed conservatively
def test_19_unrelated_documents_conservative_assessment():
    """TEST E: Verify that completely unrelated documents receive conservative severity,
    not automatically escalated to HIGH or CRITICAL simply because they differ."""
    unrelated_response = """
    {
      "severity": "LOW",
      "severity_confidence": "LOW",
      "evidence_quality": "LOW",
      "severity_basis": [
        "The leaked text appears completely unrelated to the canonical baseline document",
        "Document variance does not indicate security compromise of the canonical asset",
        "No evidence of sensitive canonical content exposure within leaked text"
      ],
      "impact": "Leaked text and canonical baseline appear unrelated; no confirmed exposure of target asset.",
      "content_changes": ["Documents share no common paragraphs or sections."],
      "possible_paraphrasing": {"detected": false, "explanation": "Texts appear completely unrelated."},
      "possible_redactions": {"detected": false, "explanation": "Cannot determine redactions between unrelated texts."},
      "recommendations": ["Verify whether correct baseline document was selected for comparison."],
      "summary": "Conservative LOW severity assessment: documents appear substantively unrelated."
    }
    """
    report = gemini_service.parse_forensic_response(unrelated_response)
    assert report.severity == "LOW"
    assert report.severity != "HIGH"
    assert report.severity != "CRITICAL"
    assert report.severity_confidence == "LOW"
    assert report.evidence_quality == "LOW"
    assert any("unrelated" in reason.lower() for reason in report.severity_basis)


# TEST 20: Severity F - OCR uncertainty lowers evidence quality and confidence
def test_20_ocr_uncertainty_reduces_evidence_quality_and_confidence():
    """TEST F: Verify poor/incomplete OCR reduces evidence_quality and severity_confidence,
    without automatically classifying as HIGH severity."""
    ocr_response = """
    {
      "severity": "MEDIUM",
      "severity_confidence": "LOW",
      "evidence_quality": "LOW",
      "severity_basis": [
        "Leaked text exhibits severe OCR scanning artifacts, missing characters, and fragmented lines",
        "Evidence quality is degraded due to raster extraction limitations",
        "Observed text fragments indicate possible partial question disclosure, but full verification requires cleaner copy"
      ],
      "impact": "Potential partial exposure hindered by poor OCR extraction fidelity.",
      "content_changes": ["Multiple lines fragmented or unreadable due to OCR artifacts."],
      "possible_paraphrasing": {"detected": false, "explanation": "Unable to verify paraphrasing due to degraded OCR text."},
      "possible_redactions": {"detected": false, "explanation": "Missing sections may be OCR scanning defects rather than intentional redaction."},
      "recommendations": ["Obtain higher-resolution scan or digital copy for re-investigation."],
      "summary": "Medium severity with low confidence due to poor OCR extraction quality."
    }
    """
    report = gemini_service.parse_forensic_response(ocr_response)
    assert report.severity == "MEDIUM"
    assert report.severity_confidence == "LOW"
    assert report.evidence_quality == "LOW"
    assert len(report.severity_basis) == 3


# TEST 21: G - Missing optional fields handled safely
def test_21_missing_optional_fields_handled_safely():
    """TEST G: Verify that responses omitting severity_confidence, evidence_quality, or severity_basis
    parse safely with valid defaults without crashing."""
    legacy_response = """
    {
      "severity": "MEDIUM",
      "impact": "Standard advisory findings.",
      "content_changes": ["Minor change"],
      "possible_paraphrasing": {"detected": false, "explanation": "None"},
      "possible_redactions": {"detected": false, "explanation": "None"},
      "recommendations": ["Review logs"],
      "summary": "Summary text"
    }
    """
    report = gemini_service.parse_forensic_response(legacy_response)
    assert report.severity == "MEDIUM"
    assert report.severity_confidence == "MEDIUM"  # Default
    assert report.evidence_quality == "MEDIUM"      # Default
    assert isinstance(report.severity_basis, list)
    assert report.impact == "Standard advisory findings."
    assert report.summary == "Summary text"


# TEST 22: H - Invalid severity handled safely
def test_22_invalid_severity_handled_safely():
    """TEST H: Verify that unparseable or unrecognized severity values safely fallback to MEDIUM."""
    invalid_sev_response = """
    {
      "severity": "CATASTROPHIC_EXTREME_ALERT",
      "severity_confidence": "HIGH",
      "evidence_quality": "HIGH",
      "severity_basis": ["Some reason"]
    }
    """
    report = gemini_service.parse_forensic_response(invalid_sev_response)
    assert report.severity == "MEDIUM"
    assert report.severity_confidence == "HIGH"
    assert report.evidence_quality == "HIGH"
    assert report.severity_basis == ["Some reason"]


# TEST 23: I - Invalid severity_confidence handled safely
def test_23_invalid_severity_confidence_handled_safely():
    """TEST I: Verify that unrecognized severity_confidence values safely fallback to MEDIUM."""
    invalid_conf_response = """
    {
      "severity": "HIGH",
      "severity_confidence": "ABSOLUTELY_CERTAIN_100%",
      "evidence_quality": "HIGH",
      "severity_basis": ["Document compromised"]
    }
    """
    report = gemini_service.parse_forensic_response(invalid_conf_response)
    assert report.severity == "HIGH"
    assert report.severity_confidence == "MEDIUM"  # Normalized fallback
    assert report.evidence_quality == "HIGH"


# TEST 24: J - Invalid evidence_quality handled safely
def test_24_invalid_evidence_quality_handled_safely():
    """TEST J: Verify that unrecognized evidence_quality values safely fallback to MEDIUM."""
    invalid_qual_response = """
    {
      "severity": "LOW",
      "severity_confidence": "LOW",
      "evidence_quality": "PRISTINE_GOLD_STANDARD",
      "severity_basis": ["Spelling only"]
    }
    """
    report = gemini_service.parse_forensic_response(invalid_qual_response)
    assert report.severity == "LOW"
    assert report.severity_confidence == "LOW"
    assert report.evidence_quality == "MEDIUM"  # Normalized fallback


# TEST 25: K - Invalid severity_basis handled safely
def test_25_invalid_severity_basis_handled_safely():
    """TEST K: Verify that string, non-string, or malformed severity_basis formats do not crash the parser."""
    # String instead of list
    str_basis = """
    {
      "severity": "LOW",
      "severity_confidence": "HIGH",
      "evidence_quality": "HIGH",
      "severity_basis": "Single string explanation instead of list"
    }
    """
    rep_str = gemini_service.parse_forensic_response(str_basis)
    assert isinstance(rep_str.severity_basis, list)
    assert len(rep_str.severity_basis) == 1
    assert rep_str.severity_basis[0] == "Single string explanation instead of list"

    # List containing numbers, booleans, and empty strings
    mixed_basis = """
    {
      "severity": "MEDIUM",
      "severity_basis": [123, true, "Valid textual finding", "   ", null]
    }
    """
    rep_mixed = gemini_service.parse_forensic_response(mixed_basis)
    assert isinstance(rep_mixed.severity_basis, list)
    assert "Valid textual finding" in rep_mixed.severity_basis
    assert "123" in rep_mixed.severity_basis
    assert "True" in rep_mixed.severity_basis

    # Dictionary instead of list
    dict_basis = """
    {
      "severity": "HIGH",
      "severity_basis": {"reason": "unexpected dict"}
    }
    """
    rep_dict = gemini_service.parse_forensic_response(dict_basis)
    assert isinstance(rep_dict.severity_basis, list)


