import json
import re
import logging
from typing import Dict, Any, List
import google.generativeai as genai
import config

logger = logging.getLogger("AIScamShield.LLMEngine")

SYSTEM_PROMPT = """You are the Core AI Safety Engine of 'AI Scam Shield'.
Your task is to analyze suspicious messages, emails, chats, or transcripts, identify if they are scams, classify them, and provide simple, layperson-friendly explainable safety details.

Linguistic Scope:
Understand English, Hindi, Gujarati, Hinglish (Hindi written in Roman characters e.g. 'paise double honge'), and Gujlish (Gujarati in Roman characters e.g. 'rokan karo faido thase').

You must categorize the text into exactly one of these scam types:
- Job Scam (fake employment/task rewards)
- Investment Scam (high yield returns, quick cash double)
- Crypto Scam (wallets, seeds, fake tokens, cloud mining)
- Loan Scam (instant loans, low interest, upfront processing fees)
- Lottery Scam (drawings, KBC fake lottery, free prize draws)
- Romance Scam (online relationship request for emergency money)
- Shopping Scam (clearance sale 90% off, fake items, delivery codes)
- Phishing (updating account details, kyc pending, fake bank links)
- OTP / Account Takeover Scam (demanding OTP codes or verification codes)
- UPI Scam (GPay/PhonePe pin requests, scanning QR code to receive cash)
- Customer Support Scam (toll free support impersonation, AnyDesk/TeamViewer installs)
- Social Media Scam (followers boost, hacked recovery fees, verified badge sale)
- Unknown Scam (other suspicious behaviors)
- Safe (if the input is totally harmless)

CRITICAL INSTRUCTION FOR THE EXPLANATION FIELD:
- Write in extremely simple, friendly, jargon-free language that an elderly grandparent or a young student can immediately understand.
- Do NOT use technical jargon (like 'phishing vector', 'credential harvesting', 'cryptographic key', 'heuristic signatures', etc.).
- Instead, explain:
  1. What is the scammer's trick (e.g., 'They are pretending to be from Paytm support').
  2. What they want from you (e.g., 'They want you to share the code sent to your phone').
  3. What will happen if you do it (e.g., 'If you share it, they will log in and transfer your money').
- Keep it under 3-4 sentences, warm, clear, and reassuring.

You MUST respond ONLY with a valid JSON block, using this exact format:
{
  "scam_score": 87,
  "risk_level": "High Risk",
  "category": "Job Scam",
  "confidence": 93,
  "red_flags": [
    "Promised 5000 INR daily salary for YouTube video likes",
    "Pressure to switch conversation to Telegram"
  ],
  "recommendations": [
    "Do not pay any registration or training fees.",
    "Do not open links shared on Telegram.",
    "Block the number immediately."
  ],
  "explanation": "This is a fake job trap. The sender is trying to trick you by promising easy money for simple tasks like liking videos. Later, they will demand that you deposit your own money to unlock your payouts. Do not send them any money!"
}

Scam Score criteria:
- 0-29: Safe
- 30-54: Suspicious
- 55-79: High Risk
- 80-100: Critical

Make your response a valid JSON. Do not include any markdown fences except if necessary, but keep the JSON clean so it can be parsed with json.loads(). Ensure 'red_flags', 'recommendations', and 'explanation' are fully filled out."""

def analyze_with_llm(text: str, custom_api_key: str = None) -> Dict[str, Any]:
    """
    Analyzes the text with Gemini API. Falls back to local engine if key is missing or API errors out.
    """
    api_key = custom_api_key or config.GEMINI_API_KEY
    
    if not api_key:
        logger.info("No Gemini API key available. Running local fallback reasoning engine.")
        return get_local_fallback_analysis(text)
        
    try:
        genai.configure(api_key=api_key)
        # Use Gemini 1.5 Flash for fast response
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        prompt = f"{SYSTEM_PROMPT}\n\nInput Text to Analyze:\n\"\"\"\n{text}\n\"\"\""
        
        logger.info("Calling Gemini API...")
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        # Clean markdown wrappers if any
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        elif response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
            
        response_text = response_text.strip()
        
        # Parse JSON
        result = json.loads(response_text)
        
        # Validate critical fields
        required_keys = ["scam_score", "risk_level", "category", "confidence", "red_flags", "recommendations", "explanation"]
        for key in required_keys:
            if key not in result:
                raise ValueError(f"Missing required key in model response: {key}")
                
        logger.info("Gemini API parsed successfully.")
        return result
        
    except Exception as e:
        logger.error(f"Gemini API analysis failed or returned invalid JSON: {e}. Falling back to local analysis.")
        return get_local_fallback_analysis(text)

def get_local_fallback_analysis(text: str) -> Dict[str, Any]:
    """
    Constructs a detailed heuristic detection result based on rule matches.
    Used when API key is unavailable or fails.
    """
    from backend.rules import analyze_text_rules
    
    rules_res = analyze_text_rules(text)
    score = rules_res["rule_scam_score"]
    risk = rules_res["risk_level"]
    category = rules_res["primary_rule_category"]
    
    red_flags = rules_res["red_flags"] + rules_res["manipulation_tactics"]
    
    # Generic safety recommendations based on classification category
    recommendations = [
        "Do not share any sensitive personal information, OTPs, bank credentials, or passwords.",
        "Avoid clicking on any links or downloading files attached to this message.",
        "Verify the caller/sender identity via official independent channels before replying."
    ]
    
    if category == "Job Scam":
        recommendations.insert(0, "Never pay processing fees or security deposits to secure employment or tasks.")
        recommendations.append("Block this number and report the contact on Telegram or WhatsApp.")
        explanation = "This is a fake job offer. The sender is trying to trick you by promising easy money (like liking YouTube videos). Later, they will ask you to pay your own money to unlock more tasks. Do not pay them any money!"
    elif category == "Investment Scam" or category == "Crypto Scam":
        recommendations.insert(0, "High returns with zero risk is the signature sign of a Ponzi scheme. Consult a licensed financial advisor.")
        recommendations.append("Never send funds to personal bank accounts or unknown crypto wallets.")
        explanation = "This is a quick-money trap. They promise high returns or doubling your money in a short time. Real investments never guarantee high returns without risk. If you send them money or crypto, you will lose it."
    elif category == "Phishing":
        recommendations.insert(0, "Do not log in using links in messages. Access your official bank website or application directly.")
        explanation = "This is a fake website trap. They are pretending to be your bank or Netflix, warning that your account is blocked. They want you to click their link and type in your password or card details so they can steal them."
    elif category == "OTP / Account Takeover Scam":
        recommendations.insert(0, "Legitimate banks, companies, and service providers never ask users to share OTPs. Sharing an OTP can result in account compromise.")
        recommendations.insert(1, "OTPs are private. Under no circumstance does any official support or bank require your OTP to resolve issues.")
        explanation = "This is an account hack attempt. They are asking you to share the OTP (verification code) sent to your phone. If you share this code, they can log in as you and take over your WhatsApp, Instagram, or bank account."
    elif category == "UPI Scam":
        recommendations.insert(0, "Remember: scanning a QR code or entering your UPI PIN is ONLY done to SEND money, never to receive it.")
        explanation = "This is a bank account draining trick. They tell you that you won cashback and ask you to scan a QR code or enter your UPI PIN. Remember: entering a PIN or scanning a QR code is only done to PAY money, never to receive it."
    elif category == "Customer Support Scam":
        recommendations.insert(0, "Never download AnyDesk, TeamViewer, or remote access software under instruction from a customer care caller.")
        explanation = "This is a remote-control trap. They pretend to be helpline support and ask you to install AnyDesk or TeamViewer. Once you share the code, they can see your screen, control your phone, and transfer your money."
    elif category == "Lottery Scam":
        recommendations.insert(0, "Real lotteries do not ask for registration charges, tax clearances, or fees in advance to release prizes.")
        explanation = "This is a fake lottery win. They claim you won a prize (like a KBC draw) that you never entered. They will ask you to pay a small fee first to claim your big prize. Once you pay, they will disappear."
    elif category == "Safe":
        explanation = "This message looks safe. It does not contain any suspicious patterns or tricks. However, it is always a good habit to protect your private details."
        recommendations = ["Keep practicing good cyber safety habits.", "Do not click on unverified URL links."]
    else:
        explanation = f"This message triggered suspicious scam markers related to {category} and uses pressure tactics to make you panic. Please be careful."
        
    confidence = 65 if len(red_flags) > 0 else 50
    if category == "Safe":
        confidence = 80
        
    return {
        "scam_score": score,
        "risk_level": risk,
        "category": category,
        "confidence": confidence,
        "red_flags": red_flags if red_flags else ["No clear scam indicators matched, but caution is advised."],
        "recommendations": recommendations,
        "explanation": explanation
    }
