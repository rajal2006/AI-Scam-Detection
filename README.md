# AI Scam Shield 🛡️

**AI Scam Shield** is a production-ready, intelligent anti-fraud and scam detection platform built using Python and Streamlit. The application acts as a cyber safety guard for vulnerable digital users (students, senior citizens, online shoppers, and job seekers) by scanning suspicious messages, chats, screenshots, URLs, and call audio recordings for scam triggers before they fall victim to fraud.

---

## Key Features

1. **Multi-Vector Analysis**: Supports Direct Text copy-paste, Chat logs, WhatsApp `.txt` file history, Screenshot uploads (via OCR text extraction), URL safety analyzer, and Voice transcript files.
2. **Hybrid Detection Engine**: Fuses rule-based keywords, local Scikit-Learn machine learning text categorization (TF-IDF pipeline), and zero-shot LLM reasoning (Google Gemini 1.5 Flash).
3. **Multi-lingual Context Support**: Analyzes code-switching languages including English, Hindi, Gujarati, Hinglish (Hindi in Latin script e.g. `paisa double`), and Gujlish (Gujarati in Latin script e.g. `rokan karo`).
4. **Explainable AI Reasoning**: Evaluates and lists exact red flags, emotional manipulation triggers (urgency pressure, isolation threats), linguistic profiles, and provides structured safety recommendations.
5. **Interactive Admin Analytics Dashboard**: Generates Plotly metrics representing incident distributions, risk ratings, input formats split, volume trends, and displays downloadable SQLite audit logs.
6. **Safety-critical Overrides**: Automatically forces critical/high threat alerts for extreme indicators (like demands for OTPs, UPI PINs, remote desktop access, or crypto private keys).

---

## Directory Structure

```
├── app.py                     # Streamlit web application interface
├── requirements.txt           # Python library dependencies
├── README.md                  # Detailed documentation and setup guide
├── .gitignore                 # Version control exclusions (DB logs, pkls, secrets)
├── config.py                  # Logger and global paths config
├── backend/
│   ├── __init__.py
│   ├── engine.py              # Main coordinator (prediction fusion)
│   ├── rules.py               # Rules & regex heuristics database
│   ├── ml_model.py            # Local ML classification wrapper
│   ├── llm_engine.py          # Google Gemini LLM wrapper & local fallback
│   ├── url_analyzer.py        # Phishing link intelligence checker
│   └── ocr_engine.py          # Screenshot text extractor
├── utils/
│   ├── __init__.py
│   ├── db_helper.py           # SQLite logs and analytics helper
│   ├── language.py            # Script and vocabulary language identifier
│   └── voice.py               # Spoken voice transcript simulator
├── models/
│   ├── train.py               # Training pipeline script
│   └── scam_detector.pkl      # Serialized ML model checkpoint (gitignored)
├── assets/
│   └── style.css              # Cyber-security dark mode UI stylesheet
├── tests/
│   └── test_detector.py       # Comprehensive unit test suite
└── .streamlit/
    └── config.toml            # Streamlit UI theme config
```

---

## Setup and Installation

### 1. Clone & Navigate
Navigate to the project root directory:
```bash
cd "AI Scam Detection"
```

### 2. Install Dependencies
Make sure you have Python 3.9+ installed. Run:
```bash
pip install -r requirements.txt
```

*Note on OCR dependencies:*
- The OCR module utilizes **EasyOCR** by default (which works out of the box using PyTorch).
- If you prefer to use **PyTesseract** local OCR, ensure you have the Tesseract binary installed on your operating system (Mac: `brew install tesseract`, Windows: download executable from installer).
- If neither is configured, the system falls back to Gemini Vision OCR (if API key is supplied) or a friendly fallback banner.

### 3. Configure Environment Variables
Create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your_google_gemini_api_key_here
```
If you do not configure an API key, the system runs on the **Local Fallback Engine** (Rules engine + ML classifier) with zero crashes, making it 100% serverless and private.

---

## Running the Application

### 1. Train the ML Model (Optional)
The classifier automatically fits and serializes itself on first run. If you want to train it manually, run:
```bash
python models/train.py
```
This writes the model checkpoint to `models/scam_detector.pkl`.

### 2. Launch Streamlit UI
Start the Streamlit development server:
```bash
streamlit run app.py
```
The app will automatically open in your default browser at `http://localhost:8501`.

---

## Running Automated Tests

A suite of unit tests validates the URL analyzer, multilingual regex parser, language identifier, SQLite DB helper, and local ML predictions.
To run the test suite, execute:
```bash
python -m unittest tests/test_detector.py
```

---

## Deployment Guide

AI Scam Shield is configured for easy cloud deployment (such as **Streamlit Community Cloud** or **Heroku**).

### Streamlit Community Cloud
1. Upload the codebase to a GitHub repository.
2. Go to [share.streamlit.io](https://share.streamlit.io/) and select your repository.
3. In **Advanced Settings**, add your environment variables to the **Secrets** text area:
   ```toml
   GEMINI_API_KEY = "your_actual_api_key"
   ```
4. Deploy. The platform will automatically install dependencies from `requirements.txt` and run.
