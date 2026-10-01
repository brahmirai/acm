"""
document_parser.py - Text extraction from PDF and TXT documents using PyMuPDF.

Extracts underlying character streams from digital documents, preserving invisible
zero-width Unicode codepoints required for canary fingerprint recovery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

try:
    import fitz  # PyMuPDF
except ImportError:  # pragma: no cover
    fitz = None  # type: ignore


def extract_text_from_pdf(file_path: Union[str, Path]) -> str:
    """Extract raw text from a PDF file using PyMuPDF (fitz).

    PyMuPDF extracts the true Unicode text stream from the PDF content objects,
    retaining zero-width characters embedded during canary document generation.

    Uses `page.get_texttrace()` to preserve consecutive zero-width Unicode codepoints
    that standard layout-based text extractors discard as duplicate overprints.

    Args:
        file_path: Path to the PDF file.

    Returns:
        Concatenated text extracted across all pages.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a regular file or is empty.
        RuntimeError: If PyMuPDF is not installed.
    """
    if fitz is None:
        raise RuntimeError("PyMuPDF (fitz) is not installed.")

    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"PDF document not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {file_path}")

    doc = fitz.open(str(path))
    pages_text: list[str] = []

    try:
        for page in doc:
            page_extracted = ""
            # get_texttrace captures every underlying character without glyph deduplication
            try:
                trace = page.get_texttrace()
                if trace:
                    spans_text: list[str] = []
                    for span in trace:
                        chars_list = span.get("chars", [])
                        span_str = "".join(chr(c[0]) for c in chars_list)
                        if span_str:
                            spans_text.append(span_str)
                    page_extracted = "\n".join(spans_text)
                else:
                    page_extracted = page.get_text("text")
            except Exception:
                page_extracted = page.get_text("text")

            pages_text.append(page_extracted)
    finally:
        doc.close()

    return "\n\n".join(pages_text)


def extract_text_from_txt(file_path: Union[str, Path]) -> str:
    """Extract text from a plain UTF-8 text file.

    Preserves exact Unicode codepoints including zero-width steganographic markers.

    Args:
        file_path: Path to the TXT file.

    Returns:
        String content of the text file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If path is not a file.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Text file not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {file_path}")

    return path.read_text(encoding="utf-8")


def extract_document_text(file_path: Union[str, Path]) -> str:
    """Extract text from supported document formats (.pdf, .txt).

    Automatically dispatches to the appropriate parser based on file extension.

    Args:
        file_path: Path to the target document.

    Returns:
        Extracted text content.

    Raises:
        FileNotFoundError: If the target file does not exist.
        ValueError: If file format is unsupported or invalid.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Document file not found: {file_path}")

    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return extract_text_from_pdf(path)
    elif suffix == ".txt":
        return extract_text_from_txt(path)
    else:
        raise ValueError(
            f"Unsupported document format '{suffix}'. Supported formats are: .pdf, .txt"
        )
