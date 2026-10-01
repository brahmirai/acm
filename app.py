"""
app.py - CANARYDOCS Streamlit Application & Orchestration Entrypoint.

CANARYDOCS: Forensic Document Provenance & Leak Investigation
A zero-width Unicode steganography and AI-assisted forensic platform for
tracking, attributing, and analyzing leaked confidential documents.

Views:
1. 📄 Document Issuance (Embed canary fingerprint into PDF/TXT)
2. 🔍 Leak Investigation (Decode zero-width fingerprint & attribute source)
3. 🤖 AI Forensic Analysis (Gemini content delta, paraphrasing & severity)
4. 📊 Audit Registry & Dashboard (Tracked documents, recipients & issuance logs)
"""

from __future__ import annotations

import io
import logging
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

# Configure app logger writing to terminal (sys.stderr)
logger = logging.getLogger("canarydocs.app")
if not logger.handlers:
    _app_handler = logging.StreamHandler(sys.stderr)
    _app_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(_app_handler)
logger.setLevel(logging.INFO)

import streamlit as st
from dotenv import load_dotenv

import database
import document_parser
import fingerprint
import gemini_service
import investigator
from models import Document, ForensicReport, InvestigationResult, Recipient
import ocr_service
import pdf_generator
import seed_data

# Load environment variables (.env)
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="CANARYDOCS • Forensic Document Provenance",
    page_icon="🪶",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling (Cyber-Forensic GovTech Dark/Light Aesthetic)
CUSTOM_CSS = """
<style>
    /* Metric Cards */
    div[data-testid="stMetricValue"] {
        font-family: 'Consolas', 'Courier New', monospace;
        font-weight: 700;
    }
    
    /* Forensic Status Badges */
    .badge-confirmed {
        background-color: #064e3b;
        color: #34d399;
        border: 1px solid #059669;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        letter-spacing: 0.5px;
        display: inline-block;
    }
    .badge-unknown {
        background-color: #78350f;
        color: #fbbf24;
        border: 1px solid #d97706;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        display: inline-block;
    }
    .badge-nofp {
        background-color: #1e293b;
        color: #94a3b8;
        border: 1px solid #475569;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        display: inline-block;
    }
    .badge-error {
        background-color: #7f1d1d;
        color: #f87171;
        border: 1px solid #dc2626;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        display: inline-block;
    }

    /* Severity Badges */
    .severity-critical {
        background-color: #7f1d1d;
        color: #fecaca;
        border-left: 6px solid #ef4444;
        padding: 12px 16px;
        border-radius: 4px;
        margin: 10px 0;
    }
    .severity-high {
        background-color: #7c2d12;
        color: #ffedd5;
        border-left: 6px solid #f97316;
        padding: 12px 16px;
        border-radius: 4px;
        margin: 10px 0;
    }
    .severity-medium {
        background-color: #713f12;
        color: #fef9c3;
        border-left: 6px solid #eab308;
        padding: 12px 16px;
        border-radius: 4px;
        margin: 10px 0;
    }
    .severity-low {
        background-color: #1e3a8a;
        color: #dbeafe;
        border-left: 6px solid #3b82f6;
        padding: 12px 16px;
        border-radius: 4px;
        margin: 10px 0;
    }

    /* Scorecard Container */
    .forensic-card {
        background-color: rgba(30, 41, 59, 0.4);
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 20px;
    }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ==============================================================================
# Application State Initialization
# ==============================================================================

def initialize_app_state() -> None:
    """Ensure database is seeded and session state defaults exist."""
    database.init_db()

    # Automatically seed sample fixtures if database is completely empty
    stats = database.get_dashboard_stats()
    if stats["documents_issued"] == 0 or stats["recipients"] == 0:
        seed_data.seed_database(force=False)

    if "selected_view" not in st.session_state:
        st.session_state["selected_view"] = "📄 Document Issuance"

    if "investigation_result" not in st.session_state:
        st.session_state["investigation_result"] = None

    if "forensic_report" not in st.session_state:
        st.session_state["forensic_report"] = None

    if "forensic_input_original" not in st.session_state:
        st.session_state["forensic_input_original"] = ""

    if "forensic_input_leaked" not in st.session_state:
        st.session_state["forensic_input_leaked"] = ""

    if "forensic_metadata" not in st.session_state:
        st.session_state["forensic_metadata"] = {}

    if "generated_pdf_bytes" not in st.session_state:
        st.session_state["generated_pdf_bytes"] = None

    if "generated_filename" not in st.session_state:
        st.session_state["generated_filename"] = ""


# ==============================================================================
# Navigation & Sidebar
# ==============================================================================

def render_sidebar() -> str:
    """Render application sidebar navigation, settings, and telemetry.

    Returns:
        Selected navigation view name.
    """
    with st.sidebar:
        st.markdown("## 🪶 **CANARYDOCS**")
        st.caption("Forensic Document Provenance & Leak Investigation")
        st.divider()

        view_options = [
            "📄 Document Issuance",
            "🔍 Leak Investigation",
            "🤖 AI Forensic Analysis",
            "📊 Audit Registry & Stats",
        ]

        # Sync with session_state if view was set programmatically
        current_idx = 0
        if st.session_state["selected_view"] in view_options:
            current_idx = view_options.index(st.session_state["selected_view"])

        selected_view = st.radio(
            "Navigation",
            options=view_options,
            index=current_idx,
            
        )
        st.session_state["selected_view"] = selected_view

        st.divider()

        # Telemetry & Diagnostics
        st.markdown("### ⚙️ System Status")

        # Database telemetry
        stats = database.get_dashboard_stats()
        st.markdown(
            f"- **SQLite:** Connected (`{stats['documents_issued']} docs, {stats['recipients']} recipients`)"
        )

        # OCR availability telemetry
        ocr_avail = ocr_service.is_tesseract_available()
        ocr_status = "✅ Ready" if ocr_avail else "⚠️ Binary Missing"
        st.markdown(f"- **Tesseract OCR:** {ocr_status}")

        # Gemini API Status & Configuration
        gemini_env_key = os.getenv("GEMINI_API_KEY", "").strip()
        gemini_active = bool(gemini_env_key or st.session_state.get("custom_gemini_key"))
        ai_status = "✅ Active" if gemini_active else "⚠️ Key Required"
        st.markdown(f"- **Gemini AI:** {ai_status}")

        with st.expander("🔑 Gemini API Settings"):
            user_key = st.text_input(
                "Gemini API Key",
                value=st.session_state.get("custom_gemini_key", ""),
                type="password",
                help="Optional if GEMINI_API_KEY is set in .env. Enter Google AI Studio key.",
            )
            if user_key:
                clean_key = user_key.strip()
                st.session_state["custom_gemini_key"] = clean_key
                os.environ["GEMINI_API_KEY"] = clean_key
            if not gemini_active:
                st.info("Get a free key from Google AI Studio to enable AI forensic analysis.")

        st.divider()

        # Quick Demo Data Reset Action
        if st.button("🔄 Reset Demo Database", help="Reset and reseed standard NEET and UPSC demo fixtures."):
            seed_data.seed_database(force=True)
            st.session_state["investigation_result"] = None
            st.session_state["forensic_report"] = None
            st.success("Database re-seeded with official demo records.")
            st.rerun()

    return selected_view


# ==============================================================================
# View 1: Document Issuance
# ==============================================================================

def view_document_issuance() -> None:
    """Render Document Issuance & Canary Watermarking view."""
    st.markdown("## 📄 Document Issuance & Canary Fingerprinting")
    st.markdown(
        "Issue a confidential examination or policy document to an authorized recipient. "
        "CanaryDocs encodes an **invisible zero-width Unicode steganographic watermark** "
        "containing the recipient's UID before generating the official PDF."
    )

    docs = database.list_documents()
    recipients = database.list_recipients()

    if not docs or not recipients:
        st.warning(
            "Database has no documents or recipients. Please reset demo data in the sidebar "
            "or register documents and recipients in the Audit Registry & Stats view."
        )
        return

    col_left, col_right = st.columns([1, 1], gap="large")

    with col_left:
        st.markdown("### 1. Select Parameters")

        # Document Selection
        doc_names = [f"{d.id}: {d.document_name} ({d.document_type})" for d in docs]
        doc_idx = st.selectbox("Select Confidential Document", range(len(doc_names)), format_func=lambda i: doc_names[i])
        selected_doc = docs[doc_idx]

        # Recipient Selection
        rec_labels = [
            f"{r.name} • UID: {r.recipient_uid} • {r.center}"
            for r in recipients
        ]
        rec_idx = st.selectbox("Select Authorized Recipient", range(len(rec_labels)), format_func=lambda i: rec_labels[i])
        selected_rec = recipients[rec_idx]

        # Issuance metadata card
        st.markdown("#### 📋 Issuance Summary")
        st.markdown(
            f"""
            <div class="forensic-card">
                <b>Document:</b> {selected_doc.document_name}<br>
                <b>Classification:</b> {selected_doc.document_type}<br>
                <b>Authorized Recipient:</b> {selected_rec.name}<br>
                <b>Recipient UID / Watermark:</b> <code>{selected_rec.recipient_uid}</code><br>
                <b>Examination Center:</b> {selected_rec.center}<br>
                <b>Steganography Strategy:</b> Zero-width Unicode codepoints (U+200B..U+FEFF)
            </div>
            """,
            unsafe_allow_html=True,
        )

        generate_clicked = st.button("🪶 Generate Personalized Canary Document", type="primary")

    with col_right:
        st.markdown("### 2. Document Preview & Output")

        if generate_clicked:
            # 1. Register or retrieve fingerprint issuance in SQLite
            existing_fp = database.find_fingerprint(selected_rec.recipient_uid)
            if existing_fp is None:
                database.create_fingerprint(
                    document_id=selected_doc.id,  # type: ignore
                    recipient_id=selected_rec.id,  # type: ignore
                    fingerprint=selected_rec.recipient_uid,
                )

            # 2. Encode text with zero-width fingerprint
            encoded_text = fingerprint.encode_text(
                selected_doc.original_text, selected_rec.recipient_uid
            )

            # 3. Generate Canary PDF to temporary file with guaranteed cleanup
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
                tmp_pdf_path = Path(tmp_pdf.name)

            try:
                pdf_generator.generate_canary_pdf(
                    document=selected_doc,
                    recipient=selected_rec,
                    encoded_text=encoded_text,
                    output_path=tmp_pdf_path,
                )
                pdf_bytes = tmp_pdf_path.read_bytes()
            finally:
                try:
                    tmp_pdf_path.unlink()
                except OSError:
                    pass

            st.session_state["generated_pdf_bytes"] = pdf_bytes
            st.session_state["generated_filename"] = f"CANARY_{selected_rec.recipient_uid}.pdf"
            st.session_state["encoded_text_preview"] = encoded_text

            # Steganographic Telemetry
            orig_len = len(selected_doc.original_text)
            encoded_len = len(encoded_text)
            stego_chars = encoded_len - orig_len

            st.success("✅ Personalized Canary Document Generated Successfully!")

            st.markdown(
                f"""
                <div class="forensic-card">
                    <span class="badge-confirmed">PROVENANCE EMBEDDED</span><br><br>
                    <b>Target Recipient:</b> {selected_rec.name} (<code>{selected_rec.recipient_uid}</code>)<br>
                    <b>Steganographic Payload:</b> {stego_chars} invisible zero-width Unicode codepoints<br>
                    <b>Integrity Checksum:</b> 8-bit XOR verified<br>
                    <b>Framing:</b> Start Marker <code>\\u200b\\u200c</code> • End Marker <code>\\u200d\\ufeff</code><br>
                    <i>The generated PDF appears visually identical to canonical copies, but uniquely attributes leaks.</i>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Download Buttons
            st.download_button(
                label=f"📥 Download Canary PDF ({selected_rec.recipient_uid})",
                data=pdf_bytes,
                file_name=st.session_state["generated_filename"],
                mime="application/pdf",
                type="primary",
            )

            st.download_button(
                label="📄 Download Steganographic TXT",
                data=encoded_text.encode("utf-8"),
                file_name=f"CANARY_{selected_rec.recipient_uid}.txt",
                mime="text/plain",
            )

            st.divider()

            # Fast demo transfer button
            if st.button("🚀 Send to Leak Investigation Tab for Instant Verification"):
                st.session_state["test_file_bytes"] = pdf_bytes
                st.session_state["test_file_name"] = st.session_state["generated_filename"]
                st.session_state["selected_view"] = "🔍 Leak Investigation"
                st.rerun()

        else:
            st.info("Click 'Generate Personalized Canary Document' to produce a watermarked PDF.")
            with st.expander("👁️ View Canonical Document Text", expanded=True):
                st.text_area(
                    "Original Canonical Text",
                    value=selected_doc.original_text,
                    height=320,
                    disabled=True,
                )


# ==============================================================================
# View 2: Leak Investigation
# ==============================================================================

def view_leak_investigation() -> None:
    """Render Leak Investigation & Source Attribution view."""
    st.markdown("## 🔍 Leak Investigation & Source Attribution")
    st.markdown(
        "Upload a suspected leaked file (PDF, TXT, or Image/Screenshot). "
        "CanaryDocs will inspect the underlying Unicode codepoints, decode any "
        "embedded zero-width watermark, and attribute the leak to the registered recipient."
    )

    # Allow uploading file or using transferred file from Issuance
    uploaded_file = st.file_uploader(
        "Upload Leaked Document or Screenshot",
        type=["pdf", "txt", "png", "jpg", "jpeg"],
        help="Upload digital PDF/TXT to decode zero-width watermark, or image for OCR visible text extraction.",
    )

    # Check if a test file was forwarded from Issuance tab
    file_bytes = None
    file_name = ""
    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_name = uploaded_file.name
    elif "test_file_bytes" in st.session_state and st.session_state["test_file_bytes"] is not None:
        file_bytes = st.session_state["test_file_bytes"]
        file_name = st.session_state.get("test_file_name", "transferred_canary.pdf")
        st.info(f"Loaded generated artifact: `{file_name}` from Issuance tab.")
        if st.button("Clear loaded artifact"):
            del st.session_state["test_file_bytes"]
            st.rerun()

    if file_bytes is None:
        st.info("Awaiting leaked document upload. Supported formats: .pdf, .txt, .png, .jpg, .jpeg")
        return

    if len(file_bytes) == 0:
        st.warning("The uploaded file is empty (0 bytes). Please upload a valid document or screenshot.")
        return

    # Process uploaded file
    file_suffix = Path(file_name).suffix.lower()

    if file_suffix not in (".pdf", ".txt", ".png", ".jpg", ".jpeg"):
        st.error(
            f"Unsupported file format '{file_suffix or '(no extension)'}'. "
            "Supported file formats are: .pdf, .txt, .png, .jpg, .jpeg"
        )
        return

    # Save to temp file for investigation
    with tempfile.NamedTemporaryFile(suffix=file_suffix, delete=False) as tmp_file:
        tmp_file.write(file_bytes)
        tmp_path = Path(tmp_file.name)

    try:
        # Case A: Digital Document Pipeline (.pdf, .txt)
        if file_suffix in (".pdf", ".txt"):
            st.markdown("### 📋 Forensic Investigation Report")

            result = investigator.investigate_document(tmp_path)
            st.session_state["investigation_result"] = result

            # Pre-fill forensic analysis state
            if result.extracted_text:
                st.session_state["forensic_input_leaked"] = result.cleaned_text or result.extracted_text
            if result.document:
                st.session_state["forensic_input_original"] = result.document.original_text
                st.session_state["forensic_metadata"] = {
                    "document_title": result.document.document_name,
                    "recipient_name": result.recipient.name if result.recipient else "Unknown",
                    "recipient_uid": result.recipient.recipient_uid if result.recipient else (result.fingerprint or "None"),
                    "center": result.recipient.center if result.recipient else "Unknown",
                    "leak_format": f"Digital {file_suffix.upper()}",
                }

            # Render Result Scorecard
            if result.status == investigator.STATE_SOURCE_IDENTIFIED:
                st.markdown(
                    f"""
                    <div class="forensic-card" style="border: 2px solid #059669; background-color: rgba(6, 78, 59, 0.15);">
                        <span class="badge-confirmed">CONFIRMED • SOURCE IDENTIFIED</span>
                        <h3 style="color: #34d399; margin-top: 10px;">MATCH FOUND: {result.recipient.name}</h3>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr><td style="padding: 6px 0; color: #94a3b8; width: 220px;"><b>Identified Recipient:</b></td><td style="font-size: 16px; font-weight: bold;">{result.recipient.name}</td></tr>
                            <tr><td style="padding: 6px 0; color: #94a3b8;"><b>Recipient UID:</b></td><td><code>{result.recipient.recipient_uid}</code></td></tr>
                            <tr><td style="padding: 6px 0; color: #94a3b8;"><b>Examination Center:</b></td><td><b>{result.recipient.center}</b></td></tr>
                            <tr><td style="padding: 6px 0; color: #94a3b8;"><b>Associated Document:</b></td><td>{result.document.document_name}</td></tr>
                            <tr><td style="padding: 6px 0; color: #94a3b8;"><b>Decoded Fingerprint Token:</b></td><td><code>{result.fingerprint}</code></td></tr>
                            <tr><td style="padding: 6px 0; color: #94a3b8;"><b>Attribution Method:</b></td><td>Cryptographic zero-width steganographic checksum match</td></tr>
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                col_btn, _ = st.columns([1, 2])
                with col_btn:
                    if st.button("🤖 Proceed to AI Forensic Analysis ->", type="primary"):
                        st.session_state["selected_view"] = "🤖 AI Forensic Analysis"
                        st.rerun()

            elif result.status == investigator.STATE_FINGERPRINT_UNKNOWN:
                st.markdown(
                    f"""
                    <div class="forensic-card" style="border: 2px solid #d97706; background-color: rgba(120, 53, 15, 0.15);">
                        <span class="badge-unknown">FINGERPRINT DETECTED • SOURCE UNKNOWN</span>
                        <h3 style="color: #fbbf24; margin-top: 10px;">Token: {result.fingerprint}</h3>
                        <p>A valid CanaryDocs zero-width steganographic watermark was extracted and validated, but no corresponding issuance record was found in the database.</p>
                        <b>Decoded Token:</b> <code>{result.fingerprint}</code>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            elif result.status == investigator.STATE_NO_FINGERPRINT:
                st.markdown(
                    """
                    <div class="forensic-card" style="border: 2px solid #475569; background-color: rgba(30, 41, 59, 0.2);">
                        <span class="badge-nofp">NO PROVENANCE FINGERPRINT DETECTED</span>
                        <h3 style="color: #94a3b8; margin-top: 10px;">Unattributed Document</h3>
                        <p>No zero-width Unicode steganographic watermark was found in the uploaded document. The document may be an un-watermarked canonical copy, or re-typed content.</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            else:
                st.markdown(
                    f"""
                    <div class="forensic-card" style="border: 2px solid #dc2626;">
                        <span class="badge-error">INVESTIGATION ERROR</span>
                        <p>{result.message}</p>
                        <p><small>{result.details}</small></p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Deep Forensic Inspection Collapsible
            with st.expander("🔬 Deep Steganographic Inspector", expanded=False):
                raw_text = result.extracted_text or ""
                cleaned_text = result.cleaned_text or ""
                zw_chars = len(raw_text) - len(cleaned_text)

                st.markdown(f"- **Raw Codepoints Extracted:** {len(raw_text)}")
                st.markdown(f"- **Clean Visible Codepoints:** {len(cleaned_text)}")
                st.markdown(f"- **Isolated Zero-Width Codepoints:** {zw_chars}")

                # Sample zero-width codepoints
                zw_list = [c for c in raw_text if c in ("\u200b", "\u200c", "\u200d", "\ufeff")]
                if zw_list:
                    codepoints_hex = " ".join([f"U+{ord(c):04X}" for c in zw_list[:32]])
                    st.code(f"First 32 codepoints: {codepoints_hex} ...", language="text")

                st.text_area("Extracted Document Text", value=cleaned_text, height=200)

        # Case B: Raster Image / Screenshot Pipeline (.png, .jpg, .jpeg)
        elif file_suffix in ocr_service.SUPPORTED_IMAGE_EXTENSIONS:
            st.markdown("### 📷 Raster Image / Screenshot Investigation")

            st.warning(
                "⚠️ **ARCHITECTURAL FORENSIC NOTICE**: Screenshots and raster images do not contain "
                "invisible zero-width Unicode codepoints. Rasterization permanently destroys them. "
                "Provenance attribution cannot be established from an image. "
                "CanaryDocs will extract **visible printed text via OCR** as a secondary pathway for AI content analysis."
            )

            col_img, col_ocr = st.columns([1, 1], gap="medium")
            with col_img:
                st.image(file_bytes, caption="Uploaded Leaked Image / Screenshot", use_container_width=True)

            with col_ocr:
                if not ocr_service.is_tesseract_available():
                    st.error(
                        "Tesseract OCR binary is not installed in the system PATH. "
                        "OCR cannot be executed automatically on this server. "
                        "You can manually paste the visible text in the AI Forensic Analysis tab."
                    )
                else:
                    with st.spinner("Extracting visible text with Pillow & pytesseract..."):
                        try:
                            extracted_ocr_text = ocr_service.extract_text_from_image(tmp_path)
                            st.success(f"Extracted {len(extracted_ocr_text)} visible characters.")
                            st.text_area("OCR Extracted Visible Text", value=extracted_ocr_text, height=240)

                            # Select canonical document to pair with
                            docs = database.list_documents()
                            if docs:
                                doc_titles = [d.document_name for d in docs]
                                paired_doc_title = st.selectbox("Compare against Canonical Document:", doc_titles)
                                paired_doc = next(d for d in docs if d.document_name == paired_doc_title)

                                if st.button("🤖 Send OCR Text to AI Forensic Analysis ->"):
                                    st.session_state["forensic_input_leaked"] = extracted_ocr_text
                                    st.session_state["forensic_input_original"] = paired_doc.original_text
                                    st.session_state["forensic_metadata"] = {
                                        "document_title": paired_doc.document_name,
                                        "recipient_name": "Unattributed (Screenshot)",
                                        "recipient_uid": "N/A",
                                        "center": "Unattributed (Screenshot)",
                                        "leak_format": "Raster Screenshot (OCR)",
                                    }
                                    st.session_state["selected_view"] = "🤖 AI Forensic Analysis"
                                    st.rerun()
                            else:
                                st.info("No canonical documents registered in database for comparison. You can still paste canonical text in the AI Forensic Analysis view.")

                        except Exception as exc:
                            st.error(f"OCR Extraction Failed: {exc}")

        else:
            st.error(
                f"Unsupported file format '{file_suffix or '(no extension)'}'. "
                "Supported file formats are: .pdf, .txt, .png, .jpg, .jpeg"
            )

    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


# ==============================================================================
# View 3: AI Forensic Analysis
# ==============================================================================

def _format_detected_value(val: Any) -> str:
    """Format a detected flag as 'Yes' or 'No'."""
    if isinstance(val, bool):
        return "Yes" if val else "No"
    if isinstance(val, (int, float)):
        return "Yes" if val else "No"
    if isinstance(val, str):
        cleaned = val.strip().lower()
        if cleaned in ("true", "yes", "1"):
            return "Yes"
        if cleaned in ("false", "no", "0"):
            return "No"
        return val.strip()
    return "Yes" if bool(val) else "No"


def _format_structured_detection_lines(
    data: Any,
    empty_label: str = "No discrepancies detected",
    icon: str = "🔍",
) -> list[str]:
    """Format structured detection field into clean markdown bullet lines.

    Handles structured objects/dictionaries containing fields such as
    `detected` and `explanation`, displaying their actual values clearly.
    """
    if not data:
        return [f"*({empty_label})*"]

    lines: list[str] = []

    # Dictionary representation
    if isinstance(data, dict):
        if "detected" in data or "explanation" in data:
            if "detected" in data:
                det_str = _format_detected_value(data.get("detected"))
                lines.append(f"- **Detected:** {det_str}")
            if "explanation" in data and data.get("explanation"):
                lines.append(f"- **Explanation:** {data.get('explanation')}")

            # Any additional structured fields
            for k, v in data.items():
                if k not in ("detected", "explanation"):
                    label = k.replace("_", " ").title()
                    lines.append(f"- **{label}:** {v}")
        else:
            for k, v in data.items():
                label = k.replace("_", " ").title()
                lines.append(f"- **{label}:** {v}")

    # Object representation (e.g. dataclass or model instance)
    elif hasattr(data, "detected") or hasattr(data, "explanation"):
        if hasattr(data, "detected"):
            det_str = _format_detected_value(getattr(data, "detected"))
            lines.append(f"- **Detected:** {det_str}")
        if hasattr(data, "explanation"):
            exp_val = getattr(data, "explanation")
            if exp_val:
                lines.append(f"- **Explanation:** {exp_val}")

    # List of items
    elif isinstance(data, list):
        if not data:
            return [f"*({empty_label})*"]
        for item in data:
            if isinstance(item, dict):
                if "detected" in item or "explanation" in item:
                    if "detected" in item:
                        det_str = _format_detected_value(item.get("detected"))
                        lines.append(f"- **Detected:** {det_str}")
                    if "explanation" in item and item.get("explanation"):
                        lines.append(f"  - **Explanation:** {item.get('explanation')}")
                    for k, v in item.items():
                        if k not in ("detected", "explanation"):
                            label = k.replace("_", " ").title()
                            lines.append(f"  - **{label}:** {v}")
                else:
                    for k, v in item.items():
                        label = k.replace("_", " ").title()
                        lines.append(f"- **{label}:** {v}")
            else:
                lines.append(f"- {icon} {item}")

    # Plain string or other scalar
    else:
        lines.append(f"- {icon} {data}")

    return lines


def _render_structured_detection(
    data: Any,
    empty_label: str = "No discrepancies detected",
    icon: str = "🔍",
) -> None:
    """Render structured detection field in Streamlit."""
    for line in _format_structured_detection_lines(data, empty_label=empty_label, icon=icon):
        st.markdown(line)


def view_forensic_analysis() -> None:
    """Render Gemini AI Comparative Forensic Analysis view."""
    st.markdown("## 🤖 AI-Assisted Forensic Document Analysis")
    st.markdown(
        "Leverage **Google Gemini** to analyze content deltas, detect intentional paraphrasing, "
        "flag redacted or missing sections, and assess operational leak severity."
    )

    # Attribution boundary disclaimer
    st.info(
        "ℹ️ **FORENSIC SEPARATION OF CONCERNS**: Source attribution is established **solely** "
        "via zero-width cryptographic steganography in SQLite. Gemini analyzes textual variance, "
        "semantic drift, and security impact."
    )

    # API Key Resolution
    api_key = os.getenv("GEMINI_API_KEY", "").strip() or st.session_state.get("custom_gemini_key", "").strip()

    if not api_key:
        st.warning("⚠️ No Gemini API key detected. Please enter your API key in the sidebar or set GEMINI_API_KEY in .env.")

    # Two text areas for comparison
    col_orig, col_leak = st.columns([1, 1], gap="medium")

    docs = database.list_documents()
    with col_orig:
        st.markdown("#### 1. Canonical Reference Document")
        if docs:
            doc_titles = [d.document_name for d in docs]
            def_idx = 0
            if st.session_state.get("forensic_metadata", {}).get("document_title") in doc_titles:
                def_idx = doc_titles.index(st.session_state["forensic_metadata"]["document_title"])

            selected_ref_doc = st.selectbox("Select Canonical Baseline:", doc_titles, index=def_idx)
            matched_doc = next(d for d in docs if d.document_name == selected_ref_doc)
            original_text = st.text_area(
                "Original Text",
                value=st.session_state.get("forensic_input_original") or matched_doc.original_text,
                height=300,
            )
        else:
            original_text = st.text_area(
                "Original Text",
                value=st.session_state.get("forensic_input_original", ""),
                height=300,
            )

    with col_leak:
        st.markdown("#### 2. Leaked Document Text")
        leaked_text = st.text_area(
            "Leaked Text Content",
            value=st.session_state.get("forensic_input_leaked", ""),
            height=300,
            placeholder="Paste leaked text here or send from Leak Investigation tab...",
        )

    # Incident Metadata Inputs
    meta = st.session_state.get("forensic_metadata", {})
    with st.expander("📝 Incident Investigation Metadata", expanded=False):
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            doc_title_meta = st.text_input("Incident Document Title", value=meta.get("document_title", "Confidential Exam Document"))
            rec_name_meta = st.text_input("Attributed Recipient (if known)", value=meta.get("recipient_name", "Unattributed"))
        with col_m2:
            center_meta = st.text_input("Attributed Center (if known)", value=meta.get("center", "Unknown Center"))
            format_meta = st.text_input("Leaked Document Format", value=meta.get("leak_format", "Digital PDF"))

    incident_meta = {
        "document_title": doc_title_meta,
        "recipient_name": rec_name_meta,
        "center": center_meta,
        "leak_format": format_meta,
    }

    # Action Button
    analyze_btn = st.button("🔍 Run Gemini Forensic Analysis", type="primary", disabled=not api_key)

    if analyze_btn:
        if not api_key:
            st.error("Gemini API key is required. Please set GEMINI_API_KEY in .env or enter it in the sidebar.")
            return

        orig_clean = original_text.strip()
        leak_clean = leaked_text.strip()
        if not orig_clean and not leak_clean:
            st.error("Both Canonical Reference text and Leaked text are empty. Please provide content for both before running forensic analysis.")
            return
        elif not orig_clean:
            st.error("Canonical Reference document text is empty. Please select or paste a valid reference document.")
            return
        elif not leak_clean:
            st.error("Leaked document text is empty. Please paste leaked content or upload a document in the Leak Investigation view.")
            return

        with st.spinner("Analyzing document differences, paraphrasing, and severity with Gemini 2.5 Flash..."):
            try:
                report = gemini_service.analyze_incident(
                    original_text=original_text,
                    leaked_text=leaked_text,
                    metadata=incident_meta,
                    api_key=api_key,
                )
                st.session_state["forensic_report"] = report
            except Exception as exc:
                exc_type = type(exc).__name__
                err_clean = gemini_service.sanitize_error_message(str(exc), secret=api_key)
                logger.error("[CANARYDOCS - APP ERROR] %s: %s", exc_type, err_clean)
                st.error("Gemini Forensic Analysis failed. Please check local terminal logs for diagnostic details.")
                return

    # Display Report if available
    report = st.session_state.get("forensic_report")
    if report:
        st.divider()
        st.markdown("### 📊 Official Forensic Analysis Report")

        # Severity Card with null-safe fallbacks
        raw_sev = getattr(report, "severity", None)
        severity = str(raw_sev).strip().upper() if raw_sev else "MEDIUM"
        if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            severity = "MEDIUM"
        severity_class = f"severity-{severity.lower()}"
        summary = getattr(report, "summary", None) or getattr(report, "impact", None) or "Forensic analysis completed."

        st.markdown(
            f"""
            <div class="{severity_class}">
                <h3 style="margin: 0;">LEAK SEVERITY: {severity}</h3>
                <p style="margin: 4px 0 0 0;">{summary}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_c1, col_c2 = st.columns([1, 1], gap="medium")

        content_changes = getattr(report, "content_changes", None)
        possible_redactions = getattr(report, "possible_redactions", None)
        possible_paraphrasing = getattr(report, "possible_paraphrasing", None)
        recommendations = getattr(report, "recommendations", None)

        with col_c1:
            st.markdown("#### 🔄 Content Differences & Scope")
            if content_changes:
                if isinstance(content_changes, list):
                    for change in content_changes:
                        if isinstance(change, dict):
                            desc = change.get("description") or change.get("explanation") or change.get("change") or str(change)
                            st.markdown(f"- {desc}")
                        else:
                            st.markdown(f"- {change}")
                elif isinstance(content_changes, dict):
                    for k, v in content_changes.items():
                        st.markdown(f"- **{k.replace('_', ' ').title()}:** {v}")
                else:
                    st.markdown(f"- {content_changes}")
            else:
                st.markdown("*(No significant textual discrepancies detected)*")

            st.markdown("#### ✂️ Redactions & Missing Sections")
            _render_structured_detection(
                possible_redactions,
                empty_label="No sensitive sections appear redacted",
                icon="⚠️",
            )

        with col_c2:
            st.markdown("#### ✍️ Paraphrasing & Rewriting Analysis")
            _render_structured_detection(
                possible_paraphrasing,
                empty_label="Text matches verbatim; no paraphrasing found",
                icon="🔍",
            )

            st.markdown("#### 🛡️ Recommended Incident Response Actions")
            if recommendations:
                if isinstance(recommendations, list):
                    for rec in recommendations:
                        if isinstance(rec, dict):
                            action = rec.get("action") or rec.get("recommendation") or rec.get("description") or str(rec)
                            st.markdown(f"- [ ] {action}")
                        else:
                            st.markdown(f"- [ ] {rec}")
                elif isinstance(recommendations, dict):
                    for k, v in recommendations.items():
                        st.markdown(f"- [ ] **{k.replace('_', ' ').title()}:** {v}")
                else:
                    st.markdown(f"- [ ] {recommendations}")
            else:
                st.markdown("*(Standard forensic retention recommended)*")

        # Raw Forensic JSON Output
        with st.expander("📄 View Structured Forensic Report (JSON)"):
            report_dict = vars(report) if hasattr(report, "__dict__") else {"report": str(report)}
            st.json(report_dict)


# ==============================================================================
# View 4: Audit Registry & Dashboard
# ==============================================================================

def view_audit_log() -> None:
    """Render Provenance Audit Registry & System Statistics view."""
    st.markdown("## 📊 Provenance Audit Registry & Dashboard")
    st.markdown("Complete verifiable chain-of-custody log stored in the SQLite persistence layer.")

    stats = database.get_dashboard_stats()

    # Metric Cards (System Statistics from database layer)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Monitored Documents", stats.get("documents_issued", 0))
    c2.metric("Registered Recipients", stats.get("recipients", 0))
    c3.metric("Issued Fingerprints", stats.get("fingerprints", 0))
    c4.metric("Logged Investigations", stats.get("investigations", 0))

    st.divider()

    tab_fps, tab_docs, tab_recs, tab_sys = st.tabs([
        "📜 Issued Canary Fingerprints (Audit Trail)",
        "📄 Monitored Documents",
        "👥 Registered Recipients",
        "⚙️ System Diagnostics",
    ])

    with tab_fps:
        records = database.get_audit_records()
        st.markdown(f"### Active Canary Watermark Issuance Records ({len(records)})")
        if not records:
            st.info("No fingerprints have been issued yet. Issue documents from the Document Issuance tab.")
        else:
            table_data = []
            for r in records:
                table_data.append({
                    "Issued At": (r.get("issued_at") or "")[:19].replace("T", " "),
                    "Document Name": r.get("document_name", "Unknown"),
                    "Classification": r.get("document_type", "RESTRICTED"),
                    "Recipient Name": r.get("recipient_name", "Unknown"),
                    "Recipient UID": r.get("recipient_uid", "Unknown"),
                    "Assigned Center": r.get("recipient_center", "Unknown"),
                    "Fingerprint Token": r.get("fingerprint_token", ""),
                })
            st.dataframe(table_data, use_container_width=True)

    with tab_docs:
        docs = database.list_documents()
        st.markdown(f"### Registered Canonical Documents ({len(docs)})")
        if not docs:
            st.info("No canonical documents currently registered. Use the form below to register a document.")
        else:
            doc_rows = [
                {
                    "ID": d.id,
                    "Document Name": d.document_name,
                    "Classification": d.document_type,
                    "Character Count": len(d.original_text or ""),
                    "Created At": (d.created_at or "")[:19].replace("T", " "),
                }
                for d in docs
            ]
            st.dataframe(doc_rows, use_container_width=True)

        with st.expander("➕ Register New Document"):
            with st.form("new_doc_form"):
                new_name = st.text_input("Document Name", placeholder="e.g. UPSC Prelims Mock 2026")
                new_type = st.text_input("Document Type / Classification", placeholder="e.g. RESTRICTED_EXAMINATION")
                new_content = st.text_area("Document Text Content", height=150)
                submit_doc = st.form_submit_button("Register Document")

                if submit_doc:
                    if new_name.strip() and new_content.strip():
                        database.create_document(
                            new_name.strip(),
                            new_type.strip() or "RESTRICTED_EXAMINATION",
                            new_content.strip(),
                        )
                        st.success(f"Document '{new_name}' registered successfully.")
                        st.rerun()
                    else:
                        st.error("Name and Content are required.")

    with tab_recs:
        recipients = database.list_recipients()
        st.markdown(f"### Registered Authorized Recipients ({len(recipients)})")
        if not recipients:
            st.info("No authorized recipients currently registered. Use the form below to register a recipient.")
        else:
            rec_rows = [
                {
                    "ID": r.id,
                    "Recipient UID": r.recipient_uid,
                    "Name": r.name,
                    "Assigned Center": r.center,
                }
                for r in recipients
            ]
            st.dataframe(rec_rows, use_container_width=True)

        with st.expander("➕ Register New Recipient"):
            with st.form("new_rec_form"):
                new_uid = st.text_input("Recipient UID (Unique Token)", placeholder="e.g. NEET-DEMO-099")
                new_name = st.text_input("Full Name", placeholder="e.g. Dr. Sunita Rao")
                new_center = st.text_input("Assigned Examination Center", placeholder="e.g. Govt Model School, Bhopal - Center 512")
                submit_rec = st.form_submit_button("Register Recipient")

                if submit_rec:
                    if new_uid.strip() and new_name.strip():
                        try:
                            database.create_recipient(
                                new_uid.strip(),
                                new_name.strip(),
                                new_center.strip() or "General Pool",
                            )
                            st.success(f"Recipient '{new_name}' registered successfully.")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Failed to register recipient: {exc}")
                    else:
                        st.error("UID and Name are required.")

    with tab_sys:
        st.markdown("### System Architecture & Database Diagnostics")
        db_path = database.resolve_db_path()
        st.markdown(
            f"""
            <div class="forensic-card">
                <b>Database Engine:</b> SQLite 3 with Foreign Key Constraints Enabled<br>
                <b>Database Location:</b> <code>{db_path}</code><br>
                <b>Steganography Engine:</b> Zero-width Unicode 4-character alphabet (<code>\\u200b</code>, <code>\\u200c</code>, <code>\\u200d</code>, <code>\\ufeff</code>)<br>
                <b>Encoding Framing:</b> 8-bit version header, 16-bit payload length, 8-bit XOR checksum<br>
                <b>OCR Secondary Pipeline:</b> {'Available (pytesseract + Pillow)' if ocr_service.is_tesseract_available() else 'Offline (Tesseract binary missing from system PATH)'}<br>
                <b>AI Analysis Model:</b> Google Gemini 2.5 Flash (via <code>google-genai</code>)
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("#### System Integrity Stats")
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.markdown(f"- **Total Documents in Registry:** {stats.get('documents_issued', 0)}")
            st.markdown(f"- **Total Authorized Recipients:** {stats.get('recipients', 0)}")
        with col_s2:
            st.markdown(f"- **Total Active Issued Fingerprints:** {stats.get('fingerprints', 0)}")
            st.markdown(f"- **Total Logged Leak Investigations:** {stats.get('investigations', 0)}")

        st.divider()
        st.markdown("#### Database Administration")
        col_res, _ = st.columns([1, 2])
        with col_res:
            if st.button("🔄 Reset & Reseed Demo Database", key="reset_db_tab_btn", help="Clears database and reseeds official NEET and UPSC demonstration records."):
                seed_data.seed_database(force=True)
                st.session_state["investigation_result"] = None
                st.session_state["forensic_report"] = None
                st.success("Database re-seeded with official demo records.")
                st.rerun()


# ==============================================================================
# Main Dispatcher
# ==============================================================================

def main() -> None:
    """Main Streamlit execution dispatcher."""
    initialize_app_state()
    selected_view = render_sidebar()

    if selected_view == "📄 Document Issuance":
        view_document_issuance()
    elif selected_view == "🔍 Leak Investigation":
        view_leak_investigation()
    elif selected_view == "🤖 AI Forensic Analysis":
        view_forensic_analysis()
    elif selected_view == "📊 Audit Registry & Stats":
        view_audit_log()


if __name__ == "__main__":
    main()
