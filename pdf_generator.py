"""
pdf_generator.py - Personalized fictional PDF generation for CANARYDOCS.

Generates official-looking fictional confidential PDF documents using fpdf2,
embedding zero-width Unicode fingerprinted text for authorized recipients.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple, Union

try:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
except ImportError:  # pragma: no cover
    FPDF = None  # type: ignore
    XPos = None  # type: ignore
    YPos = None  # type: ignore

import fingerprint
from models import Document, Recipient

# Candidate paths for TrueType Unicode fonts that preserve zero-width characters
UNICODE_FONT_CANDIDATES: list[Tuple[str, Optional[str]]] = [
    # Windows
    (r"C:\Windows\Fonts\calibri.ttf", r"C:\Windows\Fonts\calibrib.ttf"),
    (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\segoeuib.ttf"),
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    # Linux / Debian / Cloud container paths
    (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ),
    (
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ),
    (
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ),
    # macOS paths
    (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    ),
    ("/Library/Fonts/Arial.ttf", None),
]


def _discover_unicode_font() -> Tuple[Optional[str], Optional[str]]:
    """Locate an available TrueType font on the host system that supports Unicode.

    Returns:
        Tuple of (regular_font_path, bold_font_path). Either may be None if not found.
    """
    for regular_path, bold_path in UNICODE_FONT_CANDIDATES:
        if Path(regular_path).exists():
            valid_bold = (
                bold_path if (bold_path and Path(bold_path).exists()) else None
            )
            return regular_path, valid_bold
    return None, None


class _CanaryPDF(FPDF):
    """Custom FPDF2 document generator with header, footer, and styling."""

    def __init__(
        self,
        doc_name: str,
        doc_type: str,
        font_family: str,
        has_bold: bool,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.doc_name = doc_name
        self.doc_type = doc_type
        self.font_fam = font_family
        self.has_bold = has_bold

    def header(self):
        """Render formal confidentiality header banner."""
        self.set_font(
            self.font_fam,
            style="B" if self.has_bold else "",
            size=9,
        )
        self.set_text_color(180, 20, 20)
        self.cell(
            0,
            5,
            f"NATIONAL EXAMINATION & ASSESSMENT BOARD • {self.doc_type}",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="C",
        )
        self.set_font(self.font_fam, style="", size=7)
        self.set_text_color(100, 100, 100)
        self.cell(
            0,
            4,
            "SECURE CHAIN-OF-CUSTODY TRACKED • RESTRICTED ACCESS COPY",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="C",
        )
        self.set_draw_color(200, 200, 200)
        self.set_line_width(0.3)
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(6)

    def footer(self):
        """Render confidentiality footer with page pagination."""
        self.set_y(-15)
        self.set_font(self.font_fam, style="", size=8)
        self.set_text_color(130, 130, 130)
        self.cell(
            0,
            10,
            f"CANARYDOCS PROVENANCE VERIFIED • Page {self.page_no()}/{{nb}}",
            align="C",
        )


def create_demo_neet_document() -> Document:
    """Create a fictional NEET Mock Examination 2026 document.

    Contains completely fictional examination questions for demonstration.
    Does NOT use real examination questions.

    Returns:
        Populated Document model.
    """
    fictional_questions = (
        "CANARYDOCS NEET Mock Examination 2026\n"
        "Fictional Demonstration Document • Strict Security Classification\n\n"
        "CANDIDATE INSTRUCTIONS:\n"
        "This examination paper contains restricted trial items for curriculum evaluation.\n"
        "Unauthorized reproduction, digital copying, or disclosure is strictly prohibited.\n\n"
        "SECTION A — PHYSICAL SCIENCES\n"
        "Q1. A hypothetical synthetic particle of mass m = 3.2 x 10^-27 kg traverses a non-uniform "
        "electromagnetic guide. If resonant oscillation occurs at frequency f = 4.2 MHz, determine "
        "the characteristic coupling constant under vacuum dispersion.\n"
        "    (A) 1.84 x 10^-12 J/s\n"
        "    (B) 3.68 x 10^-12 J/s\n"
        "    (C) 0.92 x 10^-12 J/s\n"
        "    (D) Zero dispersion\n\n"
        "Q2. In a closed thermodynamic chamber undergoing adiabatic expansion, an ideal monoatomic "
        "test gas undergoes volume doubling. Calculate the resulting pressure ratio P2/P1.\n"
        "    (A) 0.315\n"
        "    (B) 0.500\n"
        "    (C) 0.707\n"
        "    (D) 1.414\n\n"
        "SECTION B — MOLECULAR KINETICS & BIOCHEMISTRY\n"
        "Q3. Consider the fictional cellular enzyme complex 'Enzyme-Theta' synthesized during high-altitude "
        "osmotic adaptation. Which catalytic cofactor is primarily responsible for stabilization of the "
        "pyruvate binding pocket?\n"
        "    (A) Divalent Magnesium ion (Mg2+)\n"
        "    (B) Zinc-finger domain subunit Beta\n"
        "    (C) Synthetic prosthetic group Pyr-9\n"
        "    (D) Pyridoxal phosphate analog\n\n"
        "Q4. A biochemical reaction pathway follows pseudo-first-order rate kinetics with rate constant "
        "k = 0.045 min^-1. Estimate the elapsed time required for 75% substrate consumption.\n"
        "    (A) 15.4 minutes\n"
        "    (B) 30.8 minutes\n"
        "    (C) 46.2 minutes\n"
        "    (D) 61.6 minutes\n\n"
        "END OF EXAMINATION SECTION"
    )

    return Document(
        document_name="NEET Mock Examination 2026",
        document_type="RESTRICTED_EXAMINATION",
        original_text=fictional_questions,
    )


def generate_canary_pdf(
    document: Document,
    recipient: Recipient,
    encoded_text: str,
    output_path: Union[str, Path],
) -> Path:
    """Generate a personalized fictional confidential PDF containing the fingerprinted text.

    Renders document metadata, institutional markings, classification notices,
    and the fingerprinted body text into a clean PDF using fpdf2.

    CRITICAL SECURITY SPECIFICATION:
    The recipient UID fingerprint is NOT printed visibly on the document page.
    Instead, it is invisibly embedded inside the body text using zero-width
    Unicode steganography (fingerprint.py).

    Args:
        document: Canonical document definition.
        recipient: Target recipient for whom the canary document is prepared.
        encoded_text: Text body containing embedded zero-width Unicode fingerprint.
        output_path: Target filesystem path where the generated PDF will be written.

    Returns:
        Path pointing to the written PDF file.
    """
    if FPDF is None:
        raise RuntimeError("fpdf2 is not installed. Please install fpdf2.")

    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    # Ensure the text is indeed fingerprinted with the recipient's UID
    if fingerprint.decode_fingerprint(encoded_text) is None:
        encoded_text = fingerprint.encode_text(
            encoded_text, recipient.recipient_uid
        )

    # Locate Unicode TrueType font supporting zero-width codepoints
    font_reg, font_bold = _discover_unicode_font()

    font_family = "CanaryFont" if font_reg else "Helvetica"
    has_bold = font_bold is not None

    pdf = _CanaryPDF(
        doc_name=document.document_name,
        doc_type=document.document_type,
        font_family=font_family,
        has_bold=has_bold,
        orientation="P",
        unit="mm",
        format="A4",
    )
    pdf.set_auto_page_break(auto=True, margin=15)

    if font_reg:
        pdf.add_font(font_family, style="", fname=font_reg)
        if font_bold:
            pdf.add_font(font_family, style="B", fname=font_bold)

    pdf.set_title(document.document_name)
    pdf.set_author("National Assessment Board")
    pdf.set_subject(document.document_type)

    pdf.add_page()

    # Document Title
    pdf.set_font(font_family, style="B" if has_bold else "", size=14)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(
        0,
        8,
        document.document_name,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
        align="L",
    )

    pdf.set_font(font_family, style="", size=10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(
        0,
        5,
        "CANARYDOCS • Fictional Demonstration Document",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
        align="L",
    )
    pdf.ln(3)

    # Confidentiality Notice Box
    pdf.set_fill_color(252, 243, 243)
    pdf.set_draw_color(220, 100, 100)
    pdf.set_line_width(0.3)
    pdf.rect(pdf.get_x(), pdf.get_y(), 190, 16, style="DF")

    pdf.set_xy(pdf.get_x() + 3, pdf.get_y() + 2)
    pdf.set_font(font_family, style="B" if has_bold else "", size=8)
    pdf.set_text_color(180, 30, 30)
    pdf.cell(
        0,
        4,
        "CONFIDENTIALITY & LEGAL NOTICE:",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_x(pdf.get_x() + 3)
    pdf.set_font(font_family, style="", size=7)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(
        0,
        4,
        "This document is licensed exclusively for authorized candidate assessment. "
        "Digital watermarking and forensic tracking are active.",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.ln(6)

    # Recipient Metadata Block
    # NOTE: The recipient UID is deliberately NOT printed visibly to maintain steganography
    pdf.set_fill_color(248, 249, 250)
    pdf.set_draw_color(210, 215, 220)
    pdf.rect(pdf.get_x(), pdf.get_y(), 190, 18, style="DF")

    curr_y = pdf.get_y()
    pdf.set_xy(pdf.get_x() + 4, curr_y + 2)
    pdf.set_font(font_family, style="B" if has_bold else "", size=8)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(35, 4, "Candidate Name:")
    pdf.set_font(font_family, style="", size=8)
    pdf.cell(55, 4, recipient.name)

    pdf.set_font(font_family, style="B" if has_bold else "", size=8)
    pdf.cell(35, 4, "Assigned Center:")
    pdf.set_font(font_family, style="", size=8)
    pdf.cell(0, 4, recipient.center, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(pdf.get_x() + 4)
    pdf.set_font(font_family, style="B" if has_bold else "", size=8)
    pdf.cell(35, 4, "Clearance Status:")
    pdf.set_font(font_family, style="", size=8)
    pdf.cell(55, 4, "AUTHORIZED RECIPIENT")

    pdf.set_font(font_family, style="B" if has_bold else "", size=8)
    pdf.cell(35, 4, "Security Trace:")
    pdf.set_font(font_family, style="", size=8)
    pdf.cell(
        0,
        4,
        "EMBEDDED CANARY PROVENANCE",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.ln(8)

    # Document Body with Embedded Zero-Width Fingerprinted Text
    pdf.set_font(font_family, style="", size=9)
    pdf.set_text_color(30, 30, 30)

    # Render body paragraphs
    paragraphs = encoded_text.split("\n\n")
    for para in paragraphs:
        if para.strip():
            pdf.multi_cell(0, 5, para)
            pdf.ln(3)

    pdf.output(str(out_file))
    return out_file


def generate_personalized_pdf(
    document: Document,
    recipient: Recipient,
    output_path: Union[str, Path],
) -> Path:
    """Convenience helper that encodes document.original_text and generates canary PDF.

    Args:
        document: Canonical document model.
        recipient: Recipient receiving the document (UID becomes the fingerprint).
        output_path: Destination path for generated PDF.

    Returns:
        Path to generated PDF file.
    """
    encoded_text = fingerprint.encode_text(
        document.original_text, recipient.recipient_uid
    )
    return generate_canary_pdf(document, recipient, encoded_text, output_path)
