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
