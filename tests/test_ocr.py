"""
test_ocr.py - Forensic verification and contract tests for ocr_service.py.

Verifies:
1. Function signatures and contract requirements.
2. Explicit architectural boundary documentation (zero-width steganography limitation).
3. Prohibition against calling fingerprint.decode_fingerprint in OCR pipeline.
4. Image preprocessing operations (upscaling, grayscale, contrast).
5. Robust error handling for invalid input types, missing files, and unsupported formats.
6. Execution flow with mocked and real Tesseract engine (skipping if binary absent).
"""

from __future__ import annotations

import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image, ImageDraw

import ocr_service


def test_ocr_contract_signature():
    """Verify OCR service function signatures and exports."""
    assert hasattr(ocr_service, "extract_text_from_image")
    assert hasattr(ocr_service, "extract_text_from_image_file")
    assert hasattr(ocr_service, "preprocess_image")
    assert hasattr(ocr_service, "is_tesseract_available")

    sig_extract = inspect.signature(ocr_service.extract_text_from_image)
    assert "image_input" in sig_extract.parameters
    assert "lang" in sig_extract.parameters
    assert "config" in sig_extract.parameters

    sig_file = inspect.signature(ocr_service.extract_text_from_image_file)
    assert "file_path" in sig_file.parameters


def test_ocr_limitation_documented():
    """Verify architectural limitation is explicitly documented in docstrings."""
    module_doc = ocr_service.__doc__ or ""
    assert "zero-width" in module_doc.lower()
    assert "visible" in module_doc.lower()
    assert "raster" in module_doc.lower() or "screenshot" in module_doc.lower()

    func_doc = ocr_service.extract_text_from_image.__doc__ or ""
    assert "visible" in func_doc.lower()
    assert "zero-width" in func_doc.lower()


def test_ocr_does_not_call_fingerprint_decode():
    """Verify ocr_service does not import or call fingerprint.decode_fingerprint."""
    import ast

    service_source = Path(ocr_service.__file__).read_text(encoding="utf-8")
    tree = ast.parse(service_source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "fingerprint", "ocr_service must not import fingerprint"
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "fingerprint", "ocr_service must not import from fingerprint"
        elif isinstance(node, ast.Attribute):
            assert node.attr != "decode_fingerprint", "ocr_service must not call decode_fingerprint"
        elif isinstance(node, ast.Name):
            assert node.id != "decode_fingerprint", "ocr_service must not reference decode_fingerprint"


def test_ocr_preprocessing():
    """Verify image preprocessing pipeline upscales small images and converts to grayscale."""
    small_image = Image.new("RGB", (100, 100), color=(255, 255, 255))
    processed = ocr_service.preprocess_image(small_image)

    # Small image should be upscaled
    assert processed.width >= 200
    assert processed.height >= 200
    # Mode should be grayscale ('L')
    assert processed.mode == "L"


def test_ocr_invalid_input_type():
    """Verify TypeError is raised when input is neither a Path/str nor a PIL Image."""
    with pytest.raises(TypeError, match="Expected PIL Image or filesystem path"):
        ocr_service.extract_text_from_image(12345)  # type: ignore

    with pytest.raises(TypeError, match="Expected PIL Image or filesystem path"):
        ocr_service.extract_text_from_image({"invalid": "dict"})  # type: ignore


def test_ocr_missing_file_raises_not_found(tmp_path: Path):
    """Verify FileNotFoundError is raised when image file does not exist."""
    missing_file = tmp_path / "ghost_image.png"
    with pytest.raises(FileNotFoundError, match="Image file not found"):
        ocr_service.extract_text_from_image(missing_file)


def test_ocr_unsupported_file_format(tmp_path: Path):
    """Verify ValueError is raised when file extension is not a supported image format."""
    bad_file = tmp_path / "leaked_doc.txt"
    bad_file.write_text("plain text", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported image format"):
        ocr_service.extract_text_from_image(bad_file)


def test_ocr_mocked_execution():
    """Verify end-to-end OCR extraction flow using mocked Tesseract."""
    test_image = Image.new("RGB", (320, 240), color=(255, 255, 255))

    with (
        patch("ocr_service.is_tesseract_available", return_value=True),
        patch("ocr_service.pytesseract.image_to_string", return_value="  CANARYDOCS CONFIDENTIAL  "),
    ):
        result = ocr_service.extract_text_from_image(test_image)
        assert result == "CANARYDOCS CONFIDENTIAL"


def test_ocr_mocked_binary_unavailable(tmp_path: Path):
    """Verify RuntimeError is raised when Tesseract binary is not installed."""
    img_path = tmp_path / "valid_image.png"
    Image.new("RGB", (320, 240), color=(255, 255, 255)).save(img_path)

    with patch("ocr_service.is_tesseract_available", return_value=False):
        with pytest.raises(RuntimeError, match="Tesseract OCR executable is not installed"):
            ocr_service.extract_text_from_image(img_path)


def test_ocr_extract_text_from_image_file_helper(tmp_path: Path):
    """Verify extract_text_from_image_file convenience helper calls extract_text_from_image."""
    img_path = tmp_path / "test_doc.png"
    Image.new("RGB", (320, 240), color=(255, 255, 255)).save(img_path)

    with (
        patch("ocr_service.is_tesseract_available", return_value=True),
        patch("ocr_service.pytesseract.image_to_string", return_value="VISIBLE LEAK CONTENT"),
    ):
        text = ocr_service.extract_text_from_image_file(img_path)
        assert text == "VISIBLE LEAK CONTENT"


def test_ocr_real_execution_if_tesseract_available(tmp_path: Path):
    """Verify real OCR extraction if external Tesseract binary is present in system environment."""
    if not ocr_service.is_tesseract_available():
        pytest.skip("Tesseract OCR binary not found in system PATH. Skipping live OCR test.")

    # Render a clear image with large black text on white background
    image = Image.new("RGB", (600, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)
    draw.text((20, 80), "CONFIDENTIAL CANARY EXAMINATION", fill=(0, 0, 0))

    img_file = tmp_path / "live_test.png"
    image.save(img_file)

    extracted = ocr_service.extract_text_from_image(img_file)
    assert len(extracted) > 0
    # Check that visible words were extracted
    assert any(w in extracted.upper() for w in ["CONFIDENTIAL", "CANARY", "EXAMINATION"])
