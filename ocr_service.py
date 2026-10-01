"""
ocr_service.py - Optical Character Recognition (OCR) text extraction using Pillow & pytesseract.

Provides visible text extraction for leaked screenshots, raster images, and document scans.

CRITICAL FORENSIC LIMITATION & ARCHITECTURAL CONTRACT:
-------------------------------------------------------
1. VISIBLE TEXT ONLY:
   OCR extracts printed, visible letter glyphs rendered in an image.
2. ZERO-WIDTH FINGERPRINTS DO NOT SURVIVE:
   Zero-width Unicode characters (such as zero-width spaces, joiners, or non-joiners)
   carry zero visual dimensions and have no pixel representation. Rasterization
   (screenshots, photos, image compression, scans) PERMANENTLY DESTROYS them.
3. SEPARATION OF CONCERNS:
   - Digital PDF / TXT -> Unicode Text Stream -> Zero-Width Fingerprint -> Database Attribution.
   - Leaked Image / Screenshot -> OCR -> Visible Text Only -> Gemini AI Content Comparison.
4. PROHIBITION:
   Provenance attribution (decode_fingerprint) must NEVER be attempted on OCR output.
   OCR service does NOT call fingerprint.decode_fingerprint().
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Optional, Union

try:
    from PIL import Image, ImageEnhance
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageEnhance = None  # type: ignore

try:
    import pytesseract
except ImportError:  # pragma: no cover
    pytesseract = None  # type: ignore

# Supported image file extensions
SUPPORTED_IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp")

# Default OCR parameters
DEFAULT_OCR_LANGUAGE = "eng"
DEFAULT_OCR_CONFIG = "--psm 3"


def is_tesseract_available() -> bool:
    """Check if the external Tesseract OCR binary is installed and reachable in system PATH.

    Returns:
        True if tesseract executable is installed and functional; False otherwise.
    """
    if pytesseract is None:
        return False

    # Check system PATH first
    if shutil.which("tesseract") is not None:
        return True

    # Try invoking get_tesseract_version
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def preprocess_image(image: Any) -> Any:
    """Apply sensible lightweight preprocessing to optimize OCR text extraction.

    Transformations:
    1. Upscale if image is smaller than 300px in either dimension.
    2. Convert to grayscale (L mode).
    3. Enhance contrast to sharpen character edges.

    Args:
        image: PIL Image object.

    Returns:
        Preprocessed PIL Image.
    """
    if Image is None:
        raise RuntimeError("Pillow is not installed.")

    processed = image.copy()

    # Upscale small images to improve glyph resolution
    if processed.width < 300 or processed.height < 300:
        scale_factor = 2
        processed = processed.resize(
            (processed.width * scale_factor, processed.height * scale_factor),
            resample=Image.Resampling.LANCZOS,
        )

    # Convert to grayscale
    if processed.mode != "L":
        processed = processed.convert("L")

    # Enhance contrast
    enhancer = ImageEnhance.Contrast(processed)
    processed = enhancer.enhance(1.5)

    return processed


def extract_text_from_image(
    image_input: Union[str, Path, Any],
    lang: str = DEFAULT_OCR_LANGUAGE,
    config: str = DEFAULT_OCR_CONFIG,
) -> str:
    """Extract visible text from an image using Pillow and pytesseract.

    IMPORTANT: This extracts visible printed characters only. It will NOT recover
    invisible zero-width Unicode fingerprints that were destroyed upon rasterization.

    Args:
        image_input: Filesystem path (str or Path) or PIL Image object.
        lang: Tesseract language code (default 'eng').
        config: Tesseract configuration flags (default '--psm 3').

    Returns:
        Extracted visible text string.

    Raises:
        FileNotFoundError: If the specified image path does not exist.
        ValueError: If file format is unsupported, image is empty, or input is invalid.
        TypeError: If input is neither a path nor a PIL Image.
        RuntimeError: If Tesseract OCR binary or required packages are unavailable.
    """
    if Image is None:
        raise RuntimeError("Pillow must be installed for image OCR.")

    # Resolve input into a PIL Image instance
    if isinstance(image_input, (str, Path)):
        path = Path(image_input).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Image file not found: {image_input}")
        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {image_input}")

        suffix = path.suffix.lower()
        if suffix not in SUPPORTED_IMAGE_EXTENSIONS:
            raise ValueError(
                f"Unsupported image format '{suffix}'. "
                f"Supported formats: {', '.join(SUPPORTED_IMAGE_EXTENSIONS)}"
            )

        try:
            pil_image = Image.open(str(path))
        except Exception as exc:
            raise ValueError(f"Failed to open image file '{image_input}': {exc}") from exc

    elif hasattr(image_input, "convert") and hasattr(image_input, "size"):
        pil_image = image_input
    else:
        raise TypeError(
            f"Expected PIL Image or filesystem path (str/Path), got {type(image_input).__name__}."
        )

    # Validate image dimensions
    if pil_image.width == 0 or pil_image.height == 0:
        raise ValueError("Image has zero dimensions and cannot be processed.")

    if pytesseract is None:
        raise RuntimeError("pytesseract must be installed for image OCR.")

    if not is_tesseract_available():
        raise RuntimeError(
            "Tesseract OCR executable is not installed or not found in system PATH. "
            "Please install tesseract-ocr to enable optical character recognition."
        )
    # Apply lightweight preprocessing
    processed_image = preprocess_image(pil_image)

    # Run Tesseract OCR
    try:
        extracted = pytesseract.image_to_string(
            processed_image, lang=lang, config=config
        )
        return extracted.strip()
    except Exception as exc:
        raise RuntimeError(f"Tesseract OCR execution failed: {exc}") from exc


def extract_text_from_image_file(
    file_path: Union[str, Path],
    lang: str = DEFAULT_OCR_LANGUAGE,
    config: str = DEFAULT_OCR_CONFIG,
) -> str:
    """Convenience helper to extract visible text directly from an image file path.

    Args:
        file_path: Path to target image.
        lang: Tesseract language code.
        config: Tesseract configuration flags.

    Returns:
        Extracted visible text string.
    """
    return extract_text_from_image(file_path, lang=lang, config=config)
