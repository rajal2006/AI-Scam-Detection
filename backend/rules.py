import re
from typing import Dict, List, Any

# Extensive multilingual regex patterns for scam categories and pressure tactics
RULES_DATABASE = {
    "Job Scam": [
        (r"(?i)part[\s\-]?time[\s\-]?job", "Part-time job offer with minimal requirements"),
        (r"(?i)work[\s\-]?from[\s\-]?home", "Work from home advertisement promising easy money"),
        (r"(?i)daily[\s\-]?salary|earn[\s\-]?daily", "Promising fixed daily salary payouts"),
        (r"(?i)like[\s\-]?youtube[\s\-]?(video|channel)", "YouTube video liking tasks (common task scam)"),
        (r"(?i)telegram[\s\-]?channel|join[\s\-]?telegram", "Redirecting communication to anonymous Telegram channels"),
        (r"(?i)no[\s\-]?experience[\s\-]?required", "Job offering high pay with zero experience/skills"),
        (r"(?i)(pay|earn|salary|get|paid)[\s\-]?\d{3,6}\s?(inr|rs|usd|rupees|daily)", "Promises of daily payments/salaries"),
        # Hinglish / Hindi / Gujarati
        (r"(?i)ghar[\s\-]?baithe", "Hindi/Hinglish: 'Ghar baithe' (at-home) work offer"),
        (r"(?i)naukri[\s\-]?offer|naukri[\s\-]?milegi", "Hinglish: Unsolicited 'naukri' (job) offers"),
        (r"(?i)ghare[\s\-]?betha|ghar[\s\-]?betha[\s\-]?kam", "Gujarati/Gujlish: 'Ghare betha' (Work from home) scam keywords"),
        (r"(?i)રોજગાર|નોકરી|કામ[\s\-]?આપો", "Hindi/Gujarati Script: Unsolicited job offerings in native script"),
    ],
    "Investment Scam": [
        (r"(?i)double[\s\-]?money|double[\s\-]?your[\s\-]?(money|income|investment)", "Promise to double money quickly"),
        (r"(?i)guaranteed[\s\-]?(return|profit|gain)", "Promising 'guaranteed' returns in high-risk environments"),
        (r"(?i)invest[\s\-]?\d+\s?(get|earn|return)\s?\d+", "Explicit cash investment schemes (e.g. Invest 1000 get 5000)"),
        (r"(?i)risk[\s\-]?free[\s\-]?invest", "Claiming financial investment is 100% risk-free"),
        (r"(?i)daily[\s\-]?(return|interest)\s?of?\s?\d+%", "Unrealistic daily compound interest promises"),
        # Hinglish / Hindi / Gujarati
        (r"(?i)paisa[\s\-]?double|paisa[\s\-]?duna", "Hinglish: 'Paisa double' scheme (Laxmi Chit Fund reference/trope)"),
        (r"(?i)nivesh|bina[\s\-]?risk", "Hindi/Hinglish: High-risk nivesh (investment) or risk-free claims"),
        (r"(?i)rokan|rokaad", "Gujlish: 'Rokan' (investment) promises"),
        (r"(?i)પૈસા[\s\-]?બમણા|રોકાણ|ગેરંટી[\s\-]?વળતર", "Gujarati Script: Double money / investment return guarantees"),
    ],
    "Crypto Scam": [
        (r"(?i)bitcoin[\s\-]?wallet|crypto[\s\-]?mining|binance[\s\-]?transfer", "References to sending crypto, trust wallets, or cloud mining"),
        (r"(?i)airdrop[\s\-]?claim|airdrop[\s\-]?free", "Unsolicited crypto tokens 'airdrop' claiming"),
        (r"(?i)seed[\s\-]?phrase|private[\s\-]?key", "Request for crypto seed phrase or private keys (critical threat)"),
        (r"(?i)usdt[\s\-]?deposit|trx[\s\-]?transfer|eth[\s\-]?bonus", "Instructions to transfer specific cryptocurrencies (USDT, TRX, ETH)"),
        (r"(?i)doubler[\s\-]?site|crypto[\s\-]?doubler", "Crypto doubling sites"),
    ],
    "Loan Scam": [
        (r"(?i)instant[\s\-]?loan|personal[\s\-]?loan[\s\-]?approved", "Instant loan approval messages without application"),
        (r"(?i)no[\s\-]?credit[\s\-]?check|zero[\s\-]?cibil", "Loan approval with 'no credit check' / 'low CIBIL score ok'"),
        (r"(?i)processing[\s\-]?fee[\s\-]?first|advance[\s\-]?fee", "Requesting advance processing/administrative fees before loan disbursement"),
        (r"(?i)bina[\s\-]?document|no[\s\-]?documents[\s\-]?required", "Loans requiring no verification documents"),
        (r"(?i)easy[\s\-]?loan|personal[\s\-]?loan", "Easy personal loan advertisement"),
        # Hinglish / Hindi / Gujarati
        (r"(?i)turant[\s\-]?loan|sasta[\s\-]?loan", "Hinglish: Fast/cheap loan advertisements"),
        (r"(?i)ધિરાણ|લોન[\s\-]?મંજૂર|વ્યાજ[\s\-]?વગર", "Gujarati Script: Free loans or zero interest loans"),
    ],
    "Lottery Scam": [
        (r"(?i)lucky[\s\-]?draw[\s\-]?winner|lottery[\s\-]?winner", "Claiming user won a lottery draw they never entered"),
        (r"(?i)kbc[\s\-]?lottery|kbc[\s\-]?lucky[\s\-]?draw", "Fake Kaun Banega Crorepati (KBC) lottery wins (extremely common in India)"),
        (r"(?i)congratulations[\s\-]?you[\s\-]?won|you[\s\-]?have[\s\-]?won[\s\-]?\d+", "Congratulatory lottery notices"),
        (r"(?i)spin[\s\-]?the[\s\-]?wheel|claim[\s\-]?your[\s\-]?prize", "Unsolicited links to spin wheels or claim prizes"),
        # Hinglish / Hindi / Gujarati
        (r"(?i)inaam[\s\-]?jeeta|lottery[\s\-]?lag[\s\-]?gayi", "Hinglish: 'Inaam jeeta' (Won prize) or 'Lottery lag gayi'"),
        (r"(?i)તમે[\s\-]?જીત્યા|ઇનામ[\s\-]?લાગ્યું", "Gujarati Script: Unsolicited prize winnings"),
        (r"(?i)लॉटरी[\s\-]?विजेता|इनाम[\s\-]?जीता", "Hindi Script: Lottery wins"),
    ],
    "Romance Scam": [
        (r"(?i)send[\s\-]?money[\s\-]?for[\s\-]?medical|medical[\s\-]?emergency[\s\-]?help", "Unseen online companion asking for money under medical emergency pretext"),
        (r"(?i)stuck[\s\-]?at[\s\-]?airport|stuck.*customs|custom[\s\-]?duty[\s\-]?fees|customs[\s\-]?tracker", "Claiming to send a valuable gift box, now stuck at customs requiring fees"),
        (r"(?i)buy[\s\-]?me[\s\-]?gift|gift[\s\-]?card[\s\-]?code", "Requests for steam, amazon, or Apple gift card codes from online lovers"),
        (r"(?i)marry[\s\-]?you|love[\s\-]?you[\s\-]?so[\s\-]?much", "Intense romantic declarations in very short order to build codependency"),
    ],
    "Shopping Scam": [
        (r"(?i)90%[\s\-]?off|95%[\s\-]?off|clearance[\s\-]?sale[\s\-]?today", "Unbelievably high clearance discounts (e.g. 90% off today only)"),
        (r"(?i)unbelievably[\s\-]?cheap|iphone[\s\-]?for[\s\-]?\d{3,4}", "Flagship phones advertised at ridiculously low prices (e.g. iPhone for 2000 Rs)"),
        (r"(?i)cash[\s\-]?on[\s\-]?delivery[\s\-]?verification", "Scams requesting cod verification fees"),
        (r"(?i)free[\s\-]?gift[\s\-]?card[\s\-]?claim|free[\s\-]?voucher", "Offers for free shopping vouchers"),
    ],
    "Phishing": [
        (r"(?i)verify[\s\-]?your[\s\-]?account|account[\s\-]?(suspended|blocked)", "Urgent account verification or suspension warning"),
        (r"(?i)click[\s\-]?link[\s\-]?to[\s\-]?unlock", "Suspicious directives to click link to unlock accounts"),
        (r"(?i)kyc[\s\-]?pending|kyc[\s\-]?update|pancard[\s\-]?link", "KYC update requests linking PAN cards or Aadhaar cards (highly common bank phishing)"),
        (r"(?i)update[\s\-]?bank[\s\-]?details|netbanking.*expired|profile.*expired|profile[\s\-]?has[\s\-]?expired", "Request to update netbanking details urgently"),
        (r"(?i)re-verify|reverify|username.*password", "Security alerts requiring re-verification of personal credentials"),
    ],
    "OTP / Account Takeover Scam": [
        (r"(?i)share[\s\-]?otp", "Request to share OTP"),
        (r"(?i)send[\s\-]?otp", "Request to send OTP"),
        (r"(?i)tell[\s\-]?me[\s\-]?otp", "Request to tell OTP"),
        (r"(?i)forward[\s\-]?otp", "Request to forward OTP"),
        (r"(?i)verification[\s\-]?code", "Mention of verification code"),
        (r"(?i)one[\s\-]?time[\s\-]?password", "Mention of one time password"),
        (r"(?i)security[\s\-]?code", "Mention of security code"),
        (r"(?i)login[\s\-]?code", "Mention of login code"),
        (r"(?i)authentication[\s\-]?code", "Mention of authentication code"),
        (r"(?i)otp[\s\-]?batao|code[\s\-]?batao", "Hinglish: Asking for 'OTP batao' or 'code tell me'"),
        (r"(?i)dont[\s\-]?share[\s\-]?this[\s\-]?code|don\'t[\s\-]?share[\s\-]?otp", "Copy-pasted automated notification containing safety warnings"),
        (r"(?i)verify[\s\-]?code[\s\-]?on[\s\-]?call", "Instruction to verify codes while on a telephone call"),
    ],
    "UPI Scam": [
        (r"(?i)receive[\s\-]?money[\s\-]?scan[\s\-]?qr|scan[\s\-]?qr[\s\-]?code", "Claiming user can receive money by scanning a QR code (scanning QR code always pays money, never receives)"),
        (r"(?i)upi[\s\-]?pin[\s\-]?to[\s\-]?receive", "Directing user to type in UPI PIN to 'receive' or 'claim' cash"),
        (r"(?i)request[\s\-]?money[\s\-]?on[\s\-]?(gpay|google[\s\-]?pay|paytm|phonepe)", "UPI request money prompt trickery"),
        (r"(?i)paytm[\s\-]?scratch[\s\-]?card|scratch[\s\-]?card[\s\-]?cashback", "Cashback scratch card animations linking to UPI PIN requests"),
        (r"(?i)upi[\s\-]?pin[\s\-]?daalo|pin[\s\-]?type[\s\-]?karo", "Hinglish: Instructing to type UPI PIN"),
    ],
    "Customer Support Scam": [
        (r"(?i)tech[\s\-]?support[\s\-]?helpline|toll[\s\-]?free[\s\-]?number", "Fake technical support numbers in search results/emails"),
        (r"(?i)anydesk|teamviewer|rustdesk|ultraviewer", "Requesting installation of remote access tools (AnyDesk, TeamViewer)"),
        (r"(?i)bank[\s\-]?executive[\s\-]?calling|customer[\s\-]?care[\s\-]?support", "Impersonating bank customer care or support line executives"),
    ],
    "Social Media Scam": [
        (r"(?i)hacked[\s\-]?account[\s\-]?recovery|recover[\s\-]?instagram", "Fake hacker offers to recover hacked social media accounts"),
        (r"(?i)free[\s\-]?instagram[\s\-]?followers|free[\s\-]?followers", "Websites offering free social media followers"),
        (r"(?i)verify[\s\-]?badge[\s\-]?purchase|blue[\s\-]?tick[\s\-]?free", "Free blue verification badges or bypass packages"),
        (r"(?i)giveaway[\s\-]?winner[\s\-]?click", "Social media sweepstakes giveaway winners demanding a registration/delivery fee"),
    ]
}

# Heuristics for general manipulation strategies (Urgency, Emotional Manipulation)
MANIPULATION_RULES = {
    "Urgency / Pressure": [
        (r"(?i)immediately|urgently|today[\s\-]?only|within[\s\-]?\d+[\s\-]?hours", "Urgent deadline creating high anxiety"),
        (r"(?i)last[\s\-]?chance|final[\s\-]?warning|account[\s\-]?will[\s\-]?be[\s\-]?closed", "Threat of immediate negative consequences"),
        (r"(?i)aaj[\s\-]?hi|abhi[\s\-]?karo|turant", "Hinglish: Commands for instant action ('aaj hi', 'abhi karo')"),
        (r"(?i)હમણાં[\s\-]?જ|આજે[\s\-]?જ|તાત્કાલિક", "Gujarati Script: Immediate actions ('hamna j', 'aaje j')"),
    ],
    "Authority Impersonation": [
        (r"(?i)rbi[\s\-]?governor|police[\s\-]?department|income[\s\-]?tax|cbi[\s\-]?officer", "Impersonating official investigative branches (RBI, Police, CBI, Income Tax)"),
        (r"(?i)bank[\s\-]?manager|fraud[\s\-]?department|security[\s\-]?team", "Impersonating bank manager or corporate security units"),
        (r"(?i)fedex[\s\-]?customs|dhl[\s\-]?package", "Impersonating courier delivery giants (FedEx, DHL)"),
    ],
    "Secrecy / Isolation": [
        (r"(?i)don\'t[\s\-]?tell[\s\-]?anyone|keep[\s\-]?this[\s\-]?secret", "Requesting secrecy, typical of scams trying to isolate victims"),
        (r"(?i)do[\s\-]?not[\s\-]?inform[\s\-]?family|secret[\s\-]?investigation", "Warning user not to talk to family or local police"),
        (r"(?i)kisi[\s\-]?ko[\s\-]?mat[\s\-]?batana", "Hinglish: Isolation directive ('kisi ko mat batana')"),
    ]
}

def check_otp_request(text: str) -> bool:
    """
    Checks if the text contains a request asking for, requesting,
    or manipulating the user into sharing an OTP, login code, or verification code.
    Benign messages containing OTP warnings/notifications are ignored.
    """
    if not text or not isinstance(text, str):
        return False
        
    text_lower = text.lower()
    
    # OTP nouns
    otp_nouns = [
        r"\botp\b",
        r"one[\s\-]?time[\s\-]?password",
        r"verification[\s\-]?code",
        r"security[\s\-]?code",
        r"login[\s\-]?code",
        r"authentication[\s\-]?code"
    ]
    
    # Action verbs (including Hinglish/Gujlish)
    action_verbs = [
        r"share", r"send", r"forward", r"tell", r"provide", r"give",
        r"batao", r"bhejo", r"aapo", r"moklo", r"text", r"whatsapp", r"msg", r"message"
    ]
    
    # Check if any OTP noun exists
    has_otp_noun = any(re.search(pat, text_lower) for pat in otp_nouns)
    if not has_otp_noun:
        return False
        
    # Check if any action verb exists
    has_action_verb = any(re.search(r"\b" + verb + r"\b", text_lower) for verb in action_verbs)
    if not has_action_verb:
        return False
        
    # Split text into sentences/clauses to check co-occurrence and negation
    clauses = re.split(r"[,.;!?\n]+", text_lower)
    
    negations = [
        r"don'?t", r"do\s+not", r"never", r"should\s+not", r"must\s+not", 
        r"na\s+karein", r"mat\s+batao", r"no\s+one", r"kisi\s+ko\s+mat",
        r"kisi\s+se\s+bhi", r"bina", r"without"
    ]
    
    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue
            
        clause_has_noun = any(re.search(pat, clause) for pat in otp_nouns)
        clause_has_verb = any(re.search(r"\b" + verb + r"\b", clause) for verb in action_verbs)
        
        if clause_has_noun and clause_has_verb:
            # Check if there is any negation in this clause preceding the action verb
            has_negation = False
            for neg in negations:
                for verb in action_verbs:
                    neg_verb_pat = r"\b" + neg + r"\b.*?\b" + verb + r"\b"
                    if re.search(neg_verb_pat, clause):
                        has_negation = True
                        break
                if has_negation:
                    break
            
            if not has_negation:
                return True
                
    # Also check if any direct scam/request phrase matches
    if not any(re.search(r"\b" + neg + r"\b", text_lower) for neg in negations):
        # Text has OTP noun and action verb, and NO negation whatsoever
        return True
        
    return False

def get_rule_weight_and_tier(category: str, description: str, text: str = "") -> tuple:
    """
    Returns (tier, weight, risk_factor_name) for a matched rule indicator.
    Tiers: "Low Risk", "Suspicious / Medium Risk", "High Risk"
    Weights: Low = 10, Medium = 30, High = 70
    """
    combined = f"{category} {description}".lower()
    text_lower = text.lower() if text else ""
    
    # 1. High Risk Indicators (Weight = 70)
    # - OTP requests
    if category == "OTP / Account Takeover Scam" and check_otp_request(text_lower):
        return "High Risk", 70, "OTP request / Account Takeover attempt"
        
    # - Password/private key requests
    if any(k in combined for k in ["seed phrase", "private key", "password request"]):
        return "High Risk", 70, "Password / Cryptographic seed phrase request"
        
    # - Bank credential requests
    if any(k in combined for k in ["bank credential", "atm pin", "card verification", "credit card info", "cvv"]):
        return "High Risk", 70, "Bank credential / Card verification request"
        
    # - UPI payment demands
    if category == "UPI Scam" or any(k in combined for k in ["upi pin", "upi pin daalo", "pin type karo"]):
        return "High Risk", 70, "UPI PIN / Payment demand"
        
    # - KYC scams
    if any(k in combined for k in ["kyc pending", "kyc update", "pancard link", "aadhaar"]):
        return "High Risk", 70, "KYC / Identity link scam"
        
    # - Account suspension threats
    if any(k in combined for k in ["suspended", "blocked", "block hone", "netbanking expired"]):
        return "High Risk", 70, "Account suspension / Blocking threat"
        
    # - Impersonation scams (Authority Impersonation, bank executives, support helpdesks asking for Anydesk/Teamviewer)
    if "impersonat" in combined or "anydesk" in combined or "teamviewer" in combined or "rustdesk" in combined:
        return "High Risk", 70, "Impersonation / Remote access request"
        
    # 2. Medium Risk Indicators (Weight = 30)
    # - Prize/lottery claims
    if category == "Lottery Scam" or "won" in combined or "lucky draw" in combined or "lottery" in combined:
        return "Suspicious / Medium Risk", 30, "Prize / Lottery claim promotion"
        
    # - Investment promotions
    if category in ["Investment Scam", "Crypto Scam"] or "double money" in combined or "guaranteed return" in combined or "nivesh" in combined or "rokan" in combined:
        return "Suspicious / Medium Risk", 30, "Unrealistic Investment promotion"
        
    # - Too-good-to-be-true offers (Job scams WFH, Shopping sales 90% off)
    if category in ["Job Scam", "Shopping Scam"] or "90% off" in combined or "95% off" in combined or "clearance sale" in combined or "work from home" in combined:
        return "Suspicious / Medium Risk", 30, "Too-good-to-be-true offer"
        
    # - Urgency/pressure tactics
    if category == "Urgency / Pressure":
        return "Suspicious / Medium Risk", 30, "Urgent action pressure tactic"
        
    # - Secrecy/isolation tactics or Romance scam emotional manipulation
    if category in ["Romance Scam", "Secrecy / Isolation"]:
        return "Suspicious / Medium Risk", 30, "Emotional manipulation / Isolation pressure"

    # 3. Low Risk Indicators (Weight = 10)
    # - Meeting reminders
    if any(k in text_lower for k in ["meeting", "zoom link", "standup", "appointment"]):
        return "Low Risk", 10, "Meeting or Appointment reminder"
        
    # - Transaction alerts (genuine, e.g. "Your account has been debited/credited")
    if any(k in text_lower for k in ["debited", "credited", "transaction alert", "bill generated", "subscription will auto-renew"]):
        return "Low Risk", 10, "Genuine transaction/billing alert"
        
    # - Delivery updates (genuine, e.g. order shipped/delivered)
    if any(k in text_lower for k in ["shipped", "packed", "delivered"]):
        return "Low Risk", 10, "Genuine delivery update"
        
    # - Genuine OTP notification (OTP keyword or warning, but NOT an active request to share)
    if "otp" in text_lower or "verification code" in text_lower or "login code" in text_lower:
        # Since it didn't match the high risk OTP request above, it's a notification/alert
        return "Low Risk", 10, "Genuine OTP / Login notification"
        
    # - Default for benign matched text in "Safe" category
    if category == "Safe":
        return "Low Risk", 10, "Normal conversation"

    # Default fallback
    return "Suspicious / Medium Risk", 20, "Unclassified suspicious signal"

def get_indicator_severity(category: str, description: str) -> str:
    """
    Dynamically maps a matched rule/indicator to a severity level:
    Low, Medium, or High.
    """
    tier, _, _ = get_rule_weight_and_tier(category, description)
    if tier == "Suspicious / Medium Risk":
        return "Medium"
    elif tier == "Low Risk":
        return "Low"
    elif tier == "High Risk":
        return "High"
    return "Medium"

def analyze_text_rules(text: str) -> Dict[str, Any]:
    """
    Scans the given input text against the regex rules database.
    Calculates weighted rule score, risk tier, and structured indicators.
    """
    if not text or not isinstance(text, str) or len(text.strip()) == 0:
        return {
            "rule_scam_score": 0,
            "risk_level": "Low Risk",
            "primary_rule_category": "Safe",
            "indicators": [],
            "red_flags": []
        }

    matched_indicators = []
    category_hits = {cat: 0 for cat in RULES_DATABASE.keys()}
    
    text_lower = text.lower()

    # 1. Check if it's an active OTP Request
    is_otp_req = check_otp_request(text)
    if is_otp_req:
        matched_indicators.append({
            "name": "Active OTP / Verification code request",
            "tier": "High Risk",
            "weight": 70,
            "category": "OTP / Account Takeover Scam"
        })
        category_hits["OTP / Account Takeover Scam"] += 1
    elif any(re.search(pat, text_lower) for pat in [r"\botp\b", r"verification[\s\-]?code", r"security[\s\-]?code", r"login[\s\-]?code"]):
        # Genuine OTP notification / warning
        matched_indicators.append({
            "name": "Genuine OTP / Login notification",
            "tier": "Low Risk",
            "weight": 10,
            "category": "Safe"
        })
        
    # 2. Check general database rules
    for category, rules in RULES_DATABASE.items():
        # Avoid double-counting OTP request / warning if already handled
        if category == "OTP / Account Takeover Scam":
            continue
            
        for pattern, description in rules:
            if re.search(pattern, text):
                tier, weight, factor_name = get_rule_weight_and_tier(category, description, text)
                # Avoid adding duplicates of the same factor
                if not any(ind["name"] == factor_name for ind in matched_indicators):
                    matched_indicators.append({
                        "name": factor_name,
                        "tier": tier,
                        "weight": weight,
                        "category": category
                    })
                    category_hits[category] += 1

    # 3. Check manipulation tactics
    for tactic, rules in MANIPULATION_RULES.items():
        for pattern, description in rules:
            if re.search(pattern, text):
                tier, weight, factor_name = get_rule_weight_and_tier(tactic, description, text)
                if not any(ind["name"] == factor_name for ind in matched_indicators):
                    matched_indicators.append({
                        "name": factor_name,
                        "tier": tier,
                        "weight": weight,
                        "category": tactic
                    })

    # 4. Check for transaction alerts, meeting reminders, etc., if no other threats are detected
    if not any(ind["tier"] == "High Risk" for ind in matched_indicators):
        # Check transaction alert
        if any(k in text_lower for k in ["debited", "credited", "transaction alert", "bill generated", "subscription will auto-renew", "anniversary"]):
            if not any(ind["name"] == "Genuine transaction/billing alert" for ind in matched_indicators):
                matched_indicators.append({
                    "name": "Genuine transaction/billing alert",
                    "tier": "Low Risk",
                    "weight": 10,
                    "category": "Safe"
                })
        # Check meeting reminder
        if any(k in text_lower for k in ["meeting", "zoom link", "standup", "appointment", "schedule"]):
            if not any(ind["name"] == "Meeting or Appointment reminder" for ind in matched_indicators):
                matched_indicators.append({
                    "name": "Meeting or Appointment reminder",
                    "tier": "Low Risk",
                    "weight": 10,
                    "category": "Safe"
                })
        # Check delivery update
        if any(k in text_lower for k in ["shipped", "packed", "delivered"]):
            if not any(ind["name"] == "Genuine delivery update" for ind in matched_indicators):
                matched_indicators.append({
                    "name": "Genuine delivery update",
                    "tier": "Low Risk",
                    "weight": 10,
                    "category": "Safe"
                })

    # Calculate rule score as sum of weights of matched indicators
    # Cap score at 100
    rule_scam_score = sum(ind["weight"] for ind in matched_indicators)
    rule_scam_score = min(max(rule_scam_score, 0), 100)

    # Determine primary category
    if is_otp_req:
        primary_rule_category = "OTP / Account Takeover Scam"
    elif sum(category_hits.values()) > 0:
        primary_rule_category = max(category_hits, key=category_hits.get)
    else:
        primary_rule_category = "Safe" if rule_scam_score < 30 else "Unknown Scam"

    # Redesign thresholds using the 3-level scale:
    # - Low Risk: score < 30
    # - Suspicious / Medium Risk: 30 <= score < 65
    # - High Risk: score >= 65
    if rule_scam_score < 30:
        risk_level = "Low Risk"
        primary_rule_category = "Safe"
    elif rule_scam_score < 65:
        risk_level = "Suspicious / Medium Risk"
    else:
        risk_level = "High Risk"

    # Create formatted red flags for backwards compatibility
    red_flags = []
    for ind in matched_indicators:
        red_flags.append(f"[{ind['tier']}] {ind['name']} (Score Contribution: +{ind['weight']})")

    return {
        "rule_scam_score": int(rule_scam_score),
        "risk_level": risk_level,
        "primary_rule_category": primary_rule_category,
        "indicators": matched_indicators,
        "red_flags": red_flags
    }
