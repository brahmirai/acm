# CANARYDOCS 📄🕵️‍♂️

**Forensic Document Provenance & Leak Investigation System**  
*National Assessment Security & Document Integrity Platform*

---

## 1. Project Overview

**CANARYDOCS** is a lightweight, forensic document provenance platform designed to trace confidential document leaks back to specific recipients with mathematical certainty.

The system issues sensitive examination and policy documents to authorized recipients with an **invisible recipient-specific zero-width Unicode steganographic watermark**. If a recipient leaks the document (as a digital PDF or TXT file) and the underlying Unicode text survives, CANARYDOCS extracts the character stream, decodes the invisible fingerprint, identifies the registered recipient via SQLite, and leverages **Google Gemini 2.5 Flash** to conduct an AI-assisted forensic comparison between the canonical baseline and the leaked text.

---

## 2. System Architecture

```
                               +-------------------------------------+
                               |           CANARYDOCS UI             |
                               |             (Streamlit)             |
                               +-------------------------------------+
                                  /            |                  \
                    Document Issuance   Leak Investigation   Forensic Analysis
                                 /              |                    \
+-----------------------------+v               v                     v+----------------------------+
|        pdf_generator        |        +---------------+              |       gemini_service       |
|           (fpdf2)           |        |  investigator |              |       (google-genai)       |
+-----------------------------+        +---------------+              +----------------------------+
               |                               |                                     |
               |                               +------------------+                  |
               |                               |                  |                  |
               v                               v                  v                  v
+-----------------------------+        +---------------+  +---------------+  +---------------------+
|         fingerprint         |        |document_parser|  |  ocr_service  |  |   Forensic Report   |
| (Zero-Width Steganography)  |<-------|   (PyMuPDF)   |  | (pytesseract) |  | Severity/Impact/Diff|
+-----------------------------+        +---------------+  +---------------+  +---------------------+
               |                               |
               v                               v
+--------------------------------------------------------------------------------------------------+
|                                           database                                               |
|                                       (SQLite: canarydocs.db)                                    |
+--------------------------------------------------------------------------------------------------+
```

---

## 3. Technology Stack & Constraints

### Approved Tech Stack
- **Language**: Python 3.11+
- **Frontend / Orchestration**: Streamlit
- **Database**: SQLite (`data/canarydocs.db`) with Foreign Key enforcement
- **AI / LLM Analysis**: Google Gemini 2.5 Flash via modern `google-genai` SDK
- **Document Text Extraction**: PyMuPDF (`fitz`) with character-level texttrace extraction
- **PDF Generation**: `fpdf2` with TrueType Unicode font embedding
- **Visible Text OCR**: Pillow (`PIL`) + `pytesseract`
- **Testing**: `pytest` (65 passing unit, contract, and integration tests)
- **Configuration**: `python-dotenv`

### Strict Architecture Exclusions
CANARYDOCS explicitly avoids heavyweight and distributed dependencies:
- ❌ No React / Next.js
- ❌ No FastAPI / Flask / REST microservices
- ❌ No PostgreSQL / MySQL / cloud databases
- ❌ No Redis / Celery / message brokers
- ❌ No Docker / Kubernetes

---

## 4. Module Inventory & Contracts

| Module | Primary Responsibility | Key Functions / Exports |
| :--- | :--- | :--- |
| [`models.py`](models.py) | Shared domain dataclasses | `Recipient`, `Document`, `FingerprintRecord`, `InvestigationResult`, `ForensicReport` |
| [`database.py`](database.py) | Dedicated SQLite persistence (Only module executing SQL) | `init_db()`, `create_document()`, `create_recipient()`, `create_fingerprint()`, `find_fingerprint()`, `get_dashboard_stats()`, `get_audit_records()` |
| [`fingerprint.py`](fingerprint.py) | Zero-width Unicode steganography engine | `encode_text()`, `decode_fingerprint()`, `remove_fingerprint()` |
| [`pdf_generator.py`](pdf_generator.py) | Personalized TrueType Canary PDF generation | `generate_canary_pdf()`, `generate_personalized_pdf()`, `create_demo_neet_document()` |
| [`document_parser.py`](document_parser.py) | Unicode codepoint preservation from PDF/TXT | `extract_text_from_pdf()`, `extract_text_from_txt()`, `extract_document_text()` |
| [`investigator.py`](investigator.py) | Leak triage & recipient attribution engine | `investigate_document()`, `investigate_raw_text()` |
| [`gemini_service.py`](gemini_service.py) | AI forensic comparative diffing | `analyze_incident()`, `get_gemini_client()`, `build_incident_metadata()` |
| [`ocr_service.py`](ocr_service.py) | Visible image text extraction (Secondary pathway) | `extract_text_from_image()`, `preprocess_image()`, `is_tesseract_available()` |
| [`seed_data.py`](seed_data.py) | Database seeder for official demonstration fixtures | `seed_database()` |
| [`app.py`](app.py) | Streamlit multi-view web application | `main()`, `view_document_issuance()`, `view_leak_investigation()`, `view_forensic_analysis()`, `view_audit_log()` |

---

## 5. Threat Model & Forensic Principles

### Zero-Width Steganography Protocol
Recipient identifiers are encoded into sequences of invisible zero-width Unicode codepoints:
- `\u200b` (Zero-Width Space) $\rightarrow$ binary `00`
- `\u200c` (Zero-Width Non-Joiner) $\rightarrow$ binary `01`
- `\u200d` (Zero-Width Joiner) $\rightarrow$ binary `10`
- `\ufeff` (Zero-Width No-Break Space / BOM) $\rightarrow$ binary `11`

**Packet Structure**:
```
[START_MARKER \u200b\u200c] + [8-bit Version] + [16-bit Payload Length] + [UTF-8 2-bit Payload] + [8-bit XOR Checksum] + [END_MARKER \u200d\ufeff]
```

### Forensic Boundaries & Separation of Concerns
1. **Digital Documents (PDF / TXT)**:
   - Underlying Unicode character stream survives copy-pasting and PDF rendering.
   - Steganographic watermark is extracted and matched against SQLite.
   - **Provenance attribution is 100% deterministic and cryptographically verified.**
2. **Raster Images & Screenshots (PNG / JPG)**:
   - Zero-width characters have zero visual geometry and carry no pixel footprint.
   - Rasterization (screen captures, camera photos, image compression) permanently destroys them.
   - **`ocr_service.py` extracts visible text only** and never attempts fingerprint attribution.
3. **AI Comparative Analysis (Google Gemini)**:
   - Gemini analyzes semantic shifts, leaked scope, deliberate paraphrasing, and redactions.
   - Gemini **never** guesses source attribution; attribution originates strictly from database lookups.
   - Gemini **never** claims definitive proof of third-party LLM involvement.

---

## 6. Critical Demonstration Workflow

Follow these steps to experience the complete end-to-end provenance pipeline:

### Step 1: Launch Application
```bash
streamlit run app.py
```
*(The database automatically seeds standard demonstration documents and recipients on first launch).*

### Step 2: Issue Canary Document (`📄 Document Issuance`)
1. Select Document: **NEET UG 2026 - Confidential Question Paper Subset (Biology)**.
2. Select Authorized Recipient: **Dr. Rajesh Sharma** (UID: `NEET-DEMO-042`, Center: *National High School, Jaipur - Center 241*).
3. Click **🪶 Generate Personalized Canary Document**.
4. Click **📥 Download Canary PDF**.
   *(Observe that the PDF is visually identical to canonical copies, but contains 74 invisible zero-width characters encoding `NEET-DEMO-042`).*
5. Click **🚀 Send to Leak Investigation Tab for Instant Verification** (or upload the downloaded PDF manually).

### Step 3: Investigate Leaked File (`🔍 Leak Investigation`)
1. Upload the downloaded Canary PDF (or plain `.txt` file).
2. The investigator extracts the underlying codepoints via PyMuPDF texttrace.
3. The system decodes the watermark and displays the **Attribution Scorecard**:
   - **Status**: `CONFIRMED • SOURCE IDENTIFIED`
   - **Identified Recipient**: `Dr. Rajesh Sharma`
   - **Recipient UID**: `NEET-DEMO-042`
   - **Examination Center**: `National High School, Jaipur - Center 241`
4. Click **🤖 Proceed to AI Forensic Analysis ->**.

### Step 4: Run AI Forensic Analysis (`🤖 AI Forensic Analysis`)
1. Ensure your Google AI Studio API key is provided in `.env` or sidebar settings.
2. Review the pre-populated Original and Leaked text.
3. Click **🔍 Run Gemini Forensic Analysis**.
4. Review the structured forensic evaluation:
   - **Leak Severity**: `CRITICAL` / `HIGH`
   - **Executive Summary**
   - **Content Differences & Scope**
   - **Paraphrasing & Rewriting Analysis**
   - **Redactions & Withheld Sections**
   - **Recommended Incident Response Protocol**

### Step 5: Review Provenance Audit Trail (`📊 Audit Registry & Stats`)
1. Inspect the complete chain-of-custody log.
2. View all tracked documents, registered recipients, and active fingerprint records in SQLite.

---

## 7. Installation & Test Suite

### Quick Start
```bash
# 1. Clone repository & install dependencies
pip install -r requirements.txt

# 2. Configure environment (Optional: for Gemini AI Analysis)
cp .env.example .env  # Or create .env with GEMINI_API_KEY=your_key_here

# 3. Seed demo fixtures (Automatic in app, or via CLI)
python seed_data.py

# 4. Run full test suite
pytest -v
```

### Test Suite Summary
```
tests/test_database.py       (10 tests: schema, foreign keys, deduplication, stats)
tests/test_fingerprint.py    (15 tests: bit packing, XOR checksum, framing, sanitization)
tests/test_pdf_generator.py  (10 tests: TrueType fonts, MuPDF round-trip NEET-DEMO-042)
tests/test_investigator.py   ( 6 tests: 3 forensic states, recipient lookups, errors)
tests/test_gemini.py         (11 tests: structured schemas, malformed JSON fallback, env keys)
tests/test_ocr.py            (10 tests: contract, image preprocessing, separation of concerns)
tests/test_app.py            ( 4 tests: Streamlit contracts, custom styling, database audit)
-----------------------------------------------------------------------------------------
TOTAL: 65 passed, 1 skipped (Tesseract host binary) in ~6.15s
```

---

## 8. License & Disclaimer
CANARYDOCS is an open-source cybersecurity demonstration tool developed for examination integrity and confidential document provenance tracking. All examination questions and institutional references included in demo fixtures are completely fictional.