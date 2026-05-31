import logging
from PIL import Image
from typing import Tuple, Optional
import config

logger = logging.getLogger("AIScamShield.OCREngine")

# Global flag caches for libraries
_EASYOCR_AVAILABLE = None
_PYTESSERACT_AVAILABLE = None
_EASYOCR_READER = None

def check_easyocr() -> bool:
    """Checks if easyocr is importable and works."""
    global _EASYOCR_AVAILABLE
    if _EASYOCR_AVAILABLE is not None:
        return _EASYOCR_AVAILABLE
    try:
        import easyocr
        _EASYOCR_AVAILABLE = True
    except ImportError:
        logger.warning("easyocr library is not installed.")
        _EASYOCR_AVAILABLE = False
    return _EASYOCR_AVAILABLE

def check_pytesseract() -> bool:
    """Checks if pytesseract is importable and tesseract binary is available."""
    global _PYTESSERACT_AVAILABLE
    if _PYTESSERACT_AVAILABLE is not None:
        return _PYTESSERACT_AVAILABLE
    try:
        import pytesseract
        # Quick check if command is available
        pytesseract.get_tesseract_version()
        _PYTESSERACT_AVAILABLE = True
    except Exception as e:
        logger.warning(f"pytesseract is not available or tesseract binary not found: {e}")
        _PYTESSERACT_AVAILABLE = False
    return _PYTESSERACT_AVAILABLE

def extract_text_from_image(image_path_or_file) -> Tuple[str, str]:
    """
    Extracts text from an image using the best available OCR engine.
    Returns (extracted_text, engine_used).
    """
    global _EASYOCR_READER
    
    # 1. Open the image to verify it is valid
    try:
        img = Image.open(image_path_or_file)
    except Exception as e:
        logger.error(f"Failed to open image file: {e}")
        return "", "None (Error opening image)"

    # 2. Try EasyOCR
    if check_easyocr():
        try:
            import easyocr
            import numpy as np
            # Convert PIL Image to numpy array if needed
            img_np = np.array(img.convert('RGB'))
            if _EASYOCR_READER is None:
                logger.info("Initializing EasyOCR Reader (English + Hindi)...")
                # GPU=False to prevent crashes on non-GPU environments
                _EASYOCR_READER = easyocr.Reader(['en', 'hi'], gpu=False)
            
            logger.info("Running EasyOCR extraction...")
            results = _EASYOCR_READER.readtext(img_np)
            if results:
                text = "\n".join([item[1] for item in results])
                if text.strip():
                    return text, "EasyOCR (English/Hindi)"
        except Exception as e:
            logger.error(f"EasyOCR extraction failed: {e}")

    # 3. Try PyTesseract
    if check_pytesseract():
        try:
            import pytesseract
            logger.info("Running PyTesseract extraction...")
            text = pytesseract.image_to_string(img)
            if text.strip():
                return text, "Tesseract OCR"
        except Exception as e:
            logger.error(f"PyTesseract extraction failed: {e}")

    # 4. Try Gemini Visual API (if API Key is configured)
    if config.GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            logger.info("Running Gemini multimodal visual OCR...")
            genai.configure(api_key=config.GEMINI_API_KEY)
            # Use gemini-1.5-flash as the multimodal model
            model = genai.GenerativeModel("gemini-1.5-flash")
            
            # Gemini expects PIL Image
            prompt = (
                "Perform OCR on this image. Extract all readable text including English, "
                "Hindi (Devanagari), Hinglish (Hindi in English letters), Gujarati, and Gujlish. "
                "Return ONLY the extracted text. Do not add any greeting, comments, or styling."
            )
            response = model.generate_content([prompt, img])
            text = response.text.strip()
            if text:
                return text, "Google Gemini Vision API"
        except Exception as e:
            logger.error(f"Gemini Vision API OCR failed: {e}")

    # 5. Friendly Fallback UI guidance
    warning_text = (
        "[Warning: System could not run local OCR models or cloud API. "
        "Please install 'tesseract-ocr' or verify your GEMINI_API_KEY in the sidebar to scan screenshots directly. "
        "For now, please copy and paste the chat text manually into the 'Direct Text' field.]"
    )
    logger.warning("All OCR options failed. Returning warning message.")
    return warning_text, "Fallback Engine (Failed to run OCR)"
