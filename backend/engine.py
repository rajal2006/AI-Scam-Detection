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
    URL analysis, and Gemini LLM to classify into a 3-level risk system.
    """
    logger.info("Starting hybrid scam analysis...")
    if not text or not isinstance(text, str) or len(text.strip()) == 0:
        return {
            "scam_score": 0,
            "risk_level": "Low Risk",
            "category": "Safe",
            "confidence": 100,
            "red_flags": ["No significant scam indicators detected."],
            "recommendations": ["Provide text or media to run analysis."],
            "explanation": "No text detected.",
            "diagnostics": {
                "triggered_rules": [],
                "risk_factors": [],
                "score_contributions": {
                    "rules_score": 0,
                    "ml_score": 0,
                    "final_score": 0
                },
                "decision_reason": "No text was provided for evaluation."
            }
        }

    # 1. URL Analysis
    urls = re.findall(URL_REGEX, text)
    url_flags = []
    url_score_boost = 0
    
    for url in urls:
        logger.info(f"Extracted URL for analysis: {url}")
        url_res = analyze_url(url)
        if url_res["is_suspicious"]:
            # URL indicators count as Medium Risk (Weight = 30) or High if severely phishing
            url_flags.extend([f"URL [{url_res['domain']}]: {r}" for r in url_res["reasons"]])
            url_score_boost = max(url_score_boost, url_res["score_impact"])

    # 2. Rule-Based Analysis
    rule_res = analyze_text_rules(text)
    
    # 3. Machine Learning Analysis
    ml_res = predict_scam_ml(text)
    
    # 4. LLM / Fallback Analysis
    llm_res = analyze_with_llm(text, custom_api_key)
    
    # --- Scoring & Fusion Model ---
    rule_score = rule_res["rule_scam_score"]
    ml_score = ml_res["ml_scam_score"]
    ml_conf = ml_res["confidence"]
    
    # Redesigned Threshold & Fusion Logic
    if ml_conf >= 80:
        local_fused_score = 0.4 * rule_score + 0.6 * ml_score
    else:
        local_fused_score = 0.7 * rule_score + 0.3 * ml_score
        
    # Include URL scan impact
    if url_flags:
        local_fused_score = max(local_fused_score, 30.0) # at least Medium Risk if suspicious link
        if url_score_boost >= 50:
            local_fused_score = max(local_fused_score, float(url_score_boost))

    # Base values from LLM if available, otherwise fallback to local fused scores
    if custom_api_key or config.GEMINI_API_KEY:
        final_score = llm_res.get("scam_score", 0)
        final_category = llm_res.get("category", "Unknown Scam")
        final_confidence = llm_res.get("confidence", 50)
        final_explanation = llm_res.get("explanation", "")
        final_red_flags = llm_res.get("red_flags", [])
        final_recommends = llm_res.get("recommendations", [])
    else:
        final_score = local_fused_score
        final_category = rule_res["primary_rule_category"]
        if final_category == "Safe" and ml_res["ml_category"] != "Safe":
            final_category = ml_res["ml_category"]
        final_confidence = ml_res["confidence"] if ml_res["ml_category"] != "Safe" else 80
        final_explanation = llm_res.get("explanation", "")
        final_red_flags = rule_res["red_flags"]
        final_recommends = llm_res.get("recommendations", [])

    # High-Threat Core Overrides:
    is_otp_req = check_otp_request(text)
    
    # Check other critical indicators
    critical_indicators = [
        "seed phrase", "private key", "share otp", "otp batao", "upi pin to receive", "upi pin daalo", "anydesk", "teamviewer"
    ]
    has_critical_signature = any(re.search(r"(?i)" + re.escape(sig), text) for sig in critical_indicators)

    if is_otp_req:
        logger.info("Detected positive OTP request. Forcing scam score to Critical / High Risk.")
        final_score = max(final_score, 85.0)
        final_category = "OTP / Account Takeover Scam"
    elif has_critical_signature and final_score < 75:
        logger.info("Critical signature matched. Forcing scam score to High Risk.")
        final_score = max(final_score, 75.0)
        if "otp" in text.lower():
            final_category = "OTP / Account Takeover Scam"
        elif "pin" in text.lower() or "upi" in text.lower():
            final_category = "UPI Scam"
        elif "key" in text.lower() or "seed" in text.lower():
            final_category = "Crypto Scam"
        elif "anydesk" in text.lower() or "teamviewer" in text.lower():
            final_category = "Customer Support Scam"

    # Redesign thresholds using the 3-level scale:
    # - Low Risk: score < 30
    # - Suspicious / Medium Risk: 30 <= score < 65
    # - High Risk: score >= 65
    final_score = int(final_score)
    if final_score < 30:
        final_risk = "Low Risk"
        final_category = "Safe"
    elif final_score < 65:
        final_risk = "Suspicious / Medium Risk"
    else:
        final_risk = "High Risk"

    # Format indicators & recommendations consistently
    clean_flags = []
    
    if final_risk == "Low Risk":
        # Format flags as [Low Risk] or [Minor Risk Signal]
        for flag in final_red_flags:
            clean_flag = re.sub(r"^\[(?:Critical|High|Medium|Low|High Risk|Low Risk|Suspicious / Medium Risk)\]\s*", "", flag)
            clean_flag = clean_flag.strip()
            # If it has a score contribution suffix, remove it
            clean_flag = re.sub(r"\s*\(Score Contribution:.*?\)", "", clean_flag)
            if not clean_flag or clean_flag.lower() in [
                "none", "none detected", "no significant scam indicators detected.",
                "no clear scam indicators matched, but caution is advised.", "empty input provided"
            ]:
                continue
            clean_flags.append(f"[Low Risk] {clean_flag}")
            
        if not clean_flags:
            # Let's add the matching Low Risk indicators from rule engine
            for ind in rule_res["indicators"]:
                clean_flags.append(f"[Low Risk] {ind['name']}")
                
        if not clean_flags:
            clean_flags = ["No significant scam indicators detected."]
            
        final_recommends = [
            "Keep practicing good cyber safety habits.",
            "Do not click on unverified URL links.",
            "Never share OTPs, passwords, or personal credentials."
        ]
        if not final_explanation or "scam markers" in final_explanation or "fake" in final_explanation.lower():
            final_explanation = "This message looks safe and is classified as Low Risk. It does not contain any threat indicators or pressure tactics. However, always exercise caution with private information."
    else:
        # Threat detected: ensure all indicators are labeled with proper severity levels
        for flag in final_red_flags:
            clean_flag = flag.strip()
            # If it has a score contribution suffix, remove it
            clean_flag = re.sub(r"\s*\(Score Contribution:.*?\)", "", clean_flag)
            if not clean_flag or clean_flag.lower() in [
                "none", "none detected", "no significant scam indicators detected.",
                "no clear scam indicators matched, but caution is advised.", "empty input provided"
            ]:
                continue
            
            # Match severity tier from rule engine if available
            tier = "Suspicious / Medium Risk"
            for ind in rule_res["indicators"]:
                if ind["name"] in clean_flag:
                    tier = ind["tier"]
                    break
            
            # Format flag with tier
            clean_flag_stripped = re.sub(r"^\[(?:Critical|High|Medium|Low|High Risk|Low Risk|Suspicious / Medium Risk)\]\s*", "", clean_flag)
            clean_flags.append(f"[{tier}] {clean_flag_stripped}")
            
        # Add URL flags if present
        for flag in url_flags:
            clean_flags.append(f"[Suspicious / Medium Risk] {flag}")
            
        if not clean_flags:
            clean_flags = ["No clear scam indicators matched, but caution is advised."]
            
        # Ensure bank security warning is appended for OTP fraud
        if final_category == "OTP / Account Takeover Scam":
            bank_warn = "Legitimate banks, companies, and service providers never ask users to share OTPs. Sharing an OTP can result in account compromise."
            final_recommends = [r for r in final_recommends if bank_warn not in r]
            final_recommends.insert(0, bank_warn)
            
            if not final_explanation or "scam markers" in final_explanation:
                final_explanation = "This is an account take over attempt. The sender is asking you to share a one-time password (OTP) or verification code. Legitimate companies and banks will never ask you to share your OTP. If you share it, they can take control of your account."

    if not final_recommends:
        final_recommends = [
            "Remain cautious about unsolicited messages.",
            "Verify any claims through official, independent contact numbers.",
            "Never share OTPs, credit cards, passwords, or personal credentials."
        ]

    # Diagnostics report details
    triggered_rules = []
    for ind in rule_res["indicators"]:
        triggered_rules.append({
            "name": ind["name"],
            "tier": ind["tier"],
            "weight": ind["weight"]
        })
    if url_flags:
        for uf in url_flags:
            triggered_rules.append({
                "name": uf,
                "tier": "Suspicious / Medium Risk",
                "weight": 30
            })
            
    risk_factors = [tr["name"] for tr in triggered_rules]
    
    if final_risk == "Low Risk":
        decision_reason = "No significant threat patterns or pressure tactics matched the input. The message behaves like a standard conversation, genuine update, or transaction confirmation."
    elif final_risk == "Suspicious / Medium Risk":
        decision_reason = "The message contains suspicious signals (like investment promotions, prize claims, or urgent deadlines), but does not request highly sensitive direct actions. Caution is recommended."
    else:
        decision_reason = f"Severe scam indicators matched ({final_category}). Message actively requests sensitive security codes (OTPs), card details, credentials, or uses coercion tactics (KYC threats / impersonation)."

    diagnostics = {
        "triggered_rules": triggered_rules,
        "risk_factors": risk_factors,
        "score_contributions": {
            "rules_score": int(rule_score),
            "ml_score": int(ml_score),
            "final_score": int(final_score)
        },
        "decision_reason": decision_reason
    }

    # Combine results
    fused_result = {
        "scam_score": int(final_score),
        "risk_level": final_risk,
        "category": final_category,
        "confidence": int(final_confidence),
        "red_flags": clean_flags,
        "recommendations": final_recommends,
        "explanation": final_explanation,
        "diagnostics": diagnostics
    }
    
    logger.info(f"Analysis completed: Score={fused_result['scam_score']}, Risk={fused_result['risk_level']}, Cat={fused_result['category']}")
    return fused_result
