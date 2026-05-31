import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Project Root Paths
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
MODELS_DIR = ROOT_DIR / "models"
UTILS_DIR = ROOT_DIR / "utils"
ASSETS_DIR = ROOT_DIR / "assets"

# Ensure directories exist
for folder in [MODELS_DIR, UTILS_DIR, ASSETS_DIR, BACKEND_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

# Configuration settings
DB_PATH = str(ROOT_DIR / "scam_detector.sqlite")
MODEL_PATH = str(MODELS_DIR / "scam_detector.pkl")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(ROOT_DIR / "scam_shield.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("AIScamShield")

# Global Scam Classifications
SCAM_CATEGORIES = [
    "Job Scam",
    "Investment Scam",
    "Crypto Scam",
    "Loan Scam",
    "Lottery Scam",
    "Romance Scam",
    "Shopping Scam",
    "Phishing",
    "OTP / Account Takeover Scam",
    "UPI Scam",
    "Customer Support Scam",
    "Social Media Scam",
    "Unknown Scam"
]

RISK_LEVELS = ["Low Risk", "Suspicious / Medium Risk", "High Risk"]

# API configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY environment variable not found. LLM reasoning engine will run in fallback mode.")
