import re
import logging
from typing import Dict, Any, List
from backend.rules import analyze_text_rules, check_otp_request, get_indicator_severity
from backend.ml_model import predict_scam_ml
from backend.llm_engine import analyze_with_llm
from backend.url_analyzer import analyze_url
import config

logger = logging.getLogger("AIScamShield.Coordinator")

# Regex to extract links/URLs from text
URL_REGEX = r'(https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,4}/[^\s<>"]*)'

def analyze_suspicious_input(text: str, custom_api_key: str = None) -> Dict[str, Any]:
    """
    Main entrance coordinator for AI Scam Shield. Fuses Rule Engine, ML Model,
    URL analysis, and Gemini LLM.
    """
    logger.info("Starting hybrid scam analysis...")
    if not text or not isinstance(text, str) or len(text.strip()) == 0:
        return {
            "scam_score": 0,
            "risk_level": "Safe",
            "category": "Safe",
            "confidence": 100,
            "red_flags": ["No significant scam indicators detected."],
            "recommendations": ["Provide text or media to run analysis."],
            "explanation": "No text detected."
        }

    # 1. URL Analysis
    urls = re.findall(URL_REGEX, text)
    url_flags = []
    url_score_boost = 0
    
    for url in urls:
        logger.info(f"Extracted URL for analysis: {url}")
        url_res = analyze_url(url)
        if url_res["is_suspicious"]:
            url_flags.extend([f"URL [{url_res['domain']}]: {r}" for r in url_res["reasons"]])
            url_score_boost = max(url_score_boost, url_res["score_impact"])

    # 2. Rule-Based Analysis
    rule_res = analyze_text_rules(text)
    
    # 3. Machine Learning Analysis
    ml_res = predict_scam_ml(text)
    
    # 4. LLM / Fallback Analysis
    llm_res = analyze_with_llm(text, custom_api_key)
    
    # --- Guardrail & Fusing Layer ---
    # Merge rules, ML, URL scans, and LLM to build a super-reliable prediction.
    # If the LLM has run, it serves as the base result, but we apply safety overrides.
    
    final_score = llm_res.get("scam_score", 0)
    final_category = llm_res.get("category", "Unknown Scam")
    final_risk = llm_res.get("risk_level", "Safe")
    final_confidence = llm_res.get("confidence", 50)
    final_red_flags = llm_res.get("red_flags", [])
    final_recommends = llm_res.get("recommendations", [])
    final_explanation = llm_res.get("explanation", "")

    # If local fallback occurred, rule_res score is used
    if not custom_api_key and not config.GEMINI_API_KEY:
        final_score = max(final_score, rule_res["rule_scam_score"])
        if rule_res["primary_rule_category"] != "Safe" and final_category == "Safe":
            final_category = rule_res["primary_rule_category"]
        # Merge local flags
        for flag in rule_res["red_flags"] + rule_res["manipulation_tactics"]:
            if flag not in final_red_flags:
                final_red_flags.append(flag)

    # Inject URL findings into red flags if they are missing
    for flag in url_flags:
        if flag not in final_red_flags:
            final_red_flags.append(flag)

    # Risk Boosting and Failsafes:
    # If rules engine or URL analysis finds severe issues, force high risk
    if url_score_boost >= 50 and final_score < 70:
        logger.info("URL risk override: Boosting scam score due to suspicious URL patterns.")
        final_score = max(final_score, int(url_score_boost))
        if final_category == "Safe" or final_category == "Unknown Scam":
            final_category = "Phishing"

    # Rule base check override for high-threat signatures
    critical_indicators = [
        "seed phrase", "private key", "share otp", "otp batao", "upi pin to receive", "upi pin daalo", "anydesk", "teamviewer"
    ]
    has_critical_signature = any(re.search(r"(?i)" + re.escape(sig), text) for sig in critical_indicators)
    
    # Direct check for OTP Request
    is_otp_req = check_otp_request(text)
    if is_otp_req:
        logger.info("Detected positive OTP request. Forcing scam score to Critical.")
        final_score = max(final_score, 85)
        final_category = "OTP / Account Takeover Scam"
    elif has_critical_signature and final_score < 80:
        logger.info("Critical Signature override: Boosting scam score to Critical.")
        final_score = max(final_score, 85)
        # Determine category based on keywords
        if "otp" in text.lower():
            final_category = "OTP / Account Takeover Scam"
        elif "pin" in text.lower() or "upi" in text.lower():
            final_category = "UPI Scam"
        elif "key" in text.lower() or "seed" in text.lower():
            final_category = "Crypto Scam"
        elif "anydesk" in text.lower() or "teamviewer" in text.lower():
            final_category = "Customer Support Scam"

    # Re-calculate Risk Level according to final score and verify consistency
    if final_score < 30:
        final_risk = "Safe"
        final_category = "Safe"
    elif final_score < 55:
        final_risk = "Suspicious"
    elif final_score < 80:
        final_risk = "High Risk"
    else:
        final_risk = "Critical"

    # Ensure consistency of Highlighted Indicators and Recommendations
    clean_flags = []
    
    if final_risk == "Safe":
        # SAFE report should not show red warning indicators directly
        for flag in final_red_flags:
            # Strip any severity prefixes
            clean_flag = re.sub(r"^\[(?:Critical|High|Medium|Low)\]\s*", "", flag)
            clean_flag = clean_flag.strip()
            if not clean_flag or clean_flag.lower() in [
                "none", "none detected", "no significant scam indicators detected.",
                "no clear scam indicators matched, but caution is advised.", "empty input provided"
            ]:
                continue
            clean_flags.append(f"[Minor Risk Signal] {clean_flag}")
            
        if not clean_flags:
            clean_flags = ["No significant scam indicators detected."]
            
        final_recommends = [
            "Keep practicing good cyber safety habits.",
            "Do not click on unverified URL links.",
            "Never share OTPs, passwords, or personal credentials."
        ]
        if not final_explanation or "scam markers" in final_explanation:
            final_explanation = "This message looks safe. It does not contain any suspicious patterns or tricks. However, it is always a good habit to protect your private details."
    else:
        # Threat detected: ensure all indicators are labeled with proper severity levels
        for flag in final_red_flags:
            clean_flag = flag.strip()
            if not clean_flag or clean_flag.lower() in [
                "none", "none detected", "no significant scam indicators detected.",
                "no clear scam indicators matched, but caution is advised.", "empty input provided"
            ]:
                continue
            
            # If already severity-labeled
            if re.match(r"^\[(?:Critical|High|Medium|Low)\]", clean_flag):
                clean_flags.append(clean_flag)
            else:
                severity = get_indicator_severity(final_category, clean_flag)
                clean_flags.append(f"[{severity}] {clean_flag}")
                
        if not clean_flags:
            clean_flags = ["No clear scam indicators matched, but caution is advised."]
            
        # Ensure bank security warning is appended for OTP fraud
        if final_category == "OTP / Account Takeover Scam":
            bank_warn = "Legitimate banks, companies, and service providers never ask users to share OTPs. Sharing an OTP can result in account compromise."
            # Remove clean warning if already there, and insert at front
            final_recommends = [r for r in final_recommends if bank_warn not in r]
            final_recommends.insert(0, bank_warn)
            
            if not final_explanation or "scam markers" in final_explanation:
                final_explanation = "This is an account take over attempt. The sender is asking you to share a one-time password (OTP) or verification code. Legitimate companies and banks will never ask you to share your OTP. If you share it, they can take control of your account."

    # Force fallback recommendations if none
    if not final_recommends:
        final_recommends = [
            "Remain cautious about unsolicited messages.",
            "Verify any claims through official, independent contact numbers.",
            "Never share OTPs, credit cards, passwords, or personal credentials."
        ]

    # Combine results
    fused_result = {
        "scam_score": int(final_score),
        "risk_level": final_risk,
        "category": final_category,
        "confidence": int(final_confidence),
        "red_flags": clean_flags,
        "recommendations": final_recommends,
        "explanation": final_explanation
    }
    
    logger.info(f"Analysis completed: Score={fused_result['scam_score']}, Risk={fused_result['risk_level']}, Cat={fused_result['category']}")
    return fused_result
