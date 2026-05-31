import re
from urllib.parse import urlparse
from typing import Dict, List, Any

# Popular brands targeted by scammers in India and globally
LEGIT_BRANDS = {
    "amazon": "amazon.com",
    "flipkart": "flipkart.com",
    "paytm": "paytm.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "sbi": "sbi.co.in",
    "icicibank": "icicibank.com",
    "hdfcbank": "hdfcbank.com",
    "netflix-in": "netflix.com",
    "jiomart": "jiomart.com",
    "phonepe": "phonepe.com"
}

# Known link shorteners
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "rebrand.ly", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "lnkd.in"
]

def edit_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein distance between two strings using DP."""
    if len(s1) < len(s2):
        return edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def analyze_url(url: str) -> Dict[str, Any]:
    """
    Parses and scores a URL for scam/phishing characteristics.
    """
    if not url:
        return {"is_suspicious": False, "reasons": [], "domain": "", "score_impact": 0}

    # Standardize URL protocol for parsing if missing
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    try:
        parsed = urlparse(clean_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        return {"is_suspicious": True, "reasons": ["Invalid URL format"], "domain": url, "score_impact": 40}

    if not hostname:
        return {"is_suspicious": False, "reasons": [], "domain": "", "score_impact": 0}

    reasons = []
    score_impact = 0

    # 1. Check for link shorteners
    domain = hostname.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    if domain in SHORTENERS:
        reasons.append(f"Shortened link ({domain}) used to hide destination URL")
        score_impact += 30

    # 2. Check for IP addresses as hostnames
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, domain):
        reasons.append("Raw IP address used instead of domain name")
        score_impact += 50

    # 3. Check for too many subdomains
    subdomain_count = domain.count(".")
    if subdomain_count >= 3:
        reasons.append(f"Excessive subdomains ({subdomain_count}) common in phishing setups")
        score_impact += 20

    # 4. Check for Phishing Keywords in Host/Path
    phishing_keywords = ["login", "verify", "secure", "update", "kyc", "bank", "account", "support", "signin", "verification", "ref-id"]
    hit_keywords = []
    for keyword in phishing_keywords:
        if keyword in path.lower() or keyword in query.lower() or (keyword in domain and keyword not in LEGIT_BRANDS):
            hit_keywords.append(keyword)
            
    if hit_keywords:
        reasons.append(f"Contains phishing keywords: {', '.join(hit_keywords)}")
        score_impact += len(hit_keywords) * 15

    # 5. Brand Impersonation Check (Typo-squatting)
    # Check if part of the domain is very close to a famous brand but not matching
    # Split by both dot and hyphen to capture terms like netflx-verify or hdfc-kyc
    domain_parts = re.split(r'[\.\-]', domain)
    for part in domain_parts:
        if not part or part in ["com", "net", "org", "co", "in", "www"]:
            continue
        for brand_name, brand_domain in LEGIT_BRANDS.items():
            if part == brand_name:
                # Legit brand domain? Check if the full domain ends with the official one
                if not domain.endswith(brand_domain):
                    reasons.append(f"Impersonates brand '{brand_name}' using unofficial domain ({domain})")
                    score_impact += 60
                break
            
            # Check Levenshtein distance for typosquatting
            dist = edit_distance(part, brand_name)
            # If distance is small (1 or 2 edits) and length is similar
            if 0 < dist <= 2 and len(part) >= 4:
                reasons.append(f"Typosquatting detected: domain part '{part}' closely resembles brand '{brand_name}' (distance: {dist})")
                score_impact += 50
                break

    # 6. Check for risky TLDs
    risky_tlds = [".xyz", ".top", ".buzz", ".work", ".info", ".online", ".club", ".tk", ".ml", ".cf", ".gq", ".ga"]
    for tld in risky_tlds:
        if domain.endswith(tld):
            reasons.append(f"Uses a high-risk cheap TLD ({tld}) commonly associated with spam")
            score_impact += 15
            break

    # Limit score impact to 100
    score_impact = min(score_impact, 100)
    is_suspicious = score_impact >= 30

    return {
        "is_suspicious": is_suspicious,
        "reasons": reasons,
        "domain": domain,
        "score_impact": score_impact
    }
