import re
import logging
from typing import Dict

logger = logging.getLogger("AIScamShield.LanguageDetector")

# Hinglish vocabulary markers
HINGLISH_KEYWORDS = [
    "paise", "paisa", "kamaye", "kamana", "naukri", "kaam", "ghar", "baithe", 
    "milega", "milegi", "karo", "karein", "jeeta", "batao", "daalo", "mat", 
    "kisi", "gayi", "lakh", "crore", "lotto", "inaam", "sabse", "sasta", "turant",
    "bina", "apna", "apne", "khata", "duna", "abhi", "jaldi", "aaj", "kal"
]

# Gujlish vocabulary markers (Gujarati in English letters)
GUJLISH_KEYWORDS = [
    "kem", "chho", "maza", "ma", "tame", "mane", "thodi", "help", "joiyye", 
    "rokan", "rokaad", "mali", "jashe", "thase", "nathi", "jokhmi", "ghare", 
    "betha", "aaje", "bapor", "pachi", "paisa", "rupia", "darek", "kam", "apnane"
]

def detect_language(text: str) -> str:
    """
    Identifies the language of the input text.
    Handles English, Hindi, Hinglish, Gujarati, Gujlish, and Mixed.
    """
    if not text or not isinstance(text, str) or len(text.strip()) == 0:
        return "Unknown"
        
    text_clean = text.lower()
    
    # 1. Script-based checks
    # Devanagari range: \u0900-\u097F
    has_devanagari = bool(re.search(r"[\u0900-\u097f]", text))
    # Gujarati range: \u0A80-\u0AFF
    has_gujarati = bool(re.search(r"[\u0A80-\u0AFF]", text))
    
    if has_devanagari and has_gujarati:
        return "Mixed (Hindi & Gujarati Script)"
    elif has_devanagari:
        return "Hindi (Devanagari Script)"
    elif has_gujarati:
        return "Gujarati (Gujarati Script)"
        
    # 2. Latin characters keywords heuristics (Hinglish/Gujlish check)
    words = set(re.findall(r"\b[a-z]{3,}\b", text_clean))
    
    hinglish_hits = sum(1 for w in words if w in HINGLISH_KEYWORDS)
    gujlish_hits = sum(1 for w in words if w in GUJLISH_KEYWORDS)
    
    if hinglish_hits >= 2 and gujlish_hits >= 2:
        return "Mixed (Hinglish & Gujlish)"
    elif gujlish_hits >= 2:
        return "Gujarati (written in English - Gujlish)"
    elif hinglish_hits >= 2:
        return "Hindi (written in English - Hinglish)"
        
    # 3. Langdetect library fallback
    try:
        from langdetect import detect
        lang_code = detect(text)
        if lang_code == "en":
            # Just verify it doesn't have Hinglish elements
            if hinglish_hits >= 1:
                return "English with Hinglish elements"
            return "English"
        elif lang_code == "hi":
            return "Hindi"
        elif lang_code == "gu":
            return "Gujarati"
        else:
            lang_mapping = {
                "mr": "Marathi",
                "bn": "Bengali",
                "ta": "Tamil",
                "te": "Telugu",
                "kn": "Kannada",
                "ml": "Malayalam",
                "es": "Spanish",
                "fr": "French",
                "de": "German"
            }
            return lang_mapping.get(lang_code, f"Other ({lang_code.upper()})")
    except Exception as e:
        logger.debug(f"Langdetect failed: {e}. Defaulting based on word checks.")
        
    # Standard Fallback
    if hinglish_hits >= 1:
        return "Hindi (written in English - Hinglish)"
    if gujlish_hits >= 1:
        return "Gujarati (written in English - Gujlish)"
        
    return "English"
