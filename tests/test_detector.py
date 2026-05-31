import os
import sys
import unittest
import tempfile
from pathlib import Path

# Add project root to path for imports
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set database and model to temp locations during testing to protect production database
import config
temp_db_file = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
temp_model_file = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False)
config.DB_PATH = temp_db_file.name
config.MODEL_PATH = temp_model_file.name

from backend.rules import analyze_text_rules
from backend.url_analyzer import analyze_url
from utils.language import detect_language
from utils.db_helper import init_db, log_scan, get_analytics_summary, clear_logs
from backend.ml_model import predict_scam_ml, load_ml_model
from models.train import train_and_save_model

class TestAIScamShield(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Force DB init
        init_db()
        # Train ML model once to temp location for testing predictions
        train_and_save_model()
        
    @classmethod
    def tearDownClass(cls):
        # Clean up temp files
        try:
            os.unlink(temp_db_file.name)
            os.unlink(temp_model_file.name)
        except Exception:
            pass

    def test_multilingual_rules(self):
        # Hinglish job scam
        res = analyze_text_rules("Ghar baithe part time job karo, get paid 5000 inr daily")
        self.assertGreaterEqual(res["rule_scam_score"], 40)
        self.assertEqual(res["primary_rule_category"], "Job Scam")
        
        # Gujarati investment scam
        res_guj = analyze_text_rules("આજે જ પૈસા બમણા કરો ગેરંટીડ વળતર")
        self.assertGreaterEqual(res_guj["rule_scam_score"], 30)
        self.assertEqual(res_guj["primary_rule_category"], "Investment Scam")
        
        # Critical pin leak
        res_pin = analyze_text_rules("UPI PIN daalo aur cashback collect karo")
        self.assertGreaterEqual(res_pin["rule_scam_score"], 70)
        self.assertIn("UPI Scam", [res_pin["primary_rule_category"], "UPI Scam"])

    def test_otp_scam_and_consistency(self):
        # Test using the orchestrator coordinator analyze_suspicious_input
        from backend.engine import analyze_suspicious_input
        
        # Case 1: Positive OTP scam request
        res1 = analyze_suspicious_input("Can you please share the OTP I accidentally sent to your number?")
        self.assertGreaterEqual(res1["scam_score"], 80)
        self.assertEqual(res1["category"], "OTP / Account Takeover Scam")
        self.assertEqual(res1["risk_level"], "Critical")
        self.assertTrue(any("Legitimate banks" in r for r in res1["recommendations"]))
        self.assertTrue(any("[Critical]" in flag for flag in res1["red_flags"]))
        
        # Case 2: Positive verification code request
        res2 = analyze_suspicious_input("Forward me the verification code you received.")
        self.assertGreaterEqual(res2["scam_score"], 80)
        self.assertEqual(res2["category"], "OTP / Account Takeover Scam")
        self.assertEqual(res2["risk_level"], "Critical")
        self.assertTrue(any("Legitimate banks" in r for r in res2["recommendations"]))
        self.assertTrue(any("[Critical]" in flag for flag in res2["red_flags"]))
        
        # Case 3: Safe informational OTP notification
        res3 = analyze_suspicious_input("Your login code is 834291. Do not share this code with anyone.")
        self.assertLess(res3["scam_score"], 30)
        self.assertEqual(res3["category"], "Safe")
        self.assertEqual(res3["risk_level"], "Safe")
        for flag in res3["red_flags"]:
            self.assertTrue("Minor Risk Signal" in flag or "No significant scam indicators" in flag)
            
        # Consistency test with mild urgency in safe context
        res_urg = analyze_suspicious_input("Meeting starts in 5 minutes, please arrive ASAP.")
        self.assertLess(res_urg["scam_score"], 30)
        self.assertEqual(res_urg["category"], "Safe")
        self.assertEqual(res_urg["risk_level"], "Safe")
        for flag in res_urg["red_flags"]:
            self.assertTrue("Minor Risk Signal" in flag or "No significant scam indicators" in flag)

    def test_url_analyzer(self):
        # Shorteners
        res_short = analyze_url("http://bit.ly/my-phish-link")
        self.assertTrue(res_short["is_suspicious"])
        self.assertIn("Shortened link", res_short["reasons"][0])
        
        # Typosquatting
        res_typo = analyze_url("https://netflx-account-renew.com/login.php")
        self.assertTrue(res_typo["is_suspicious"])
        self.assertTrue(any("Typosquatting" in r or "Impersonates" in r for r in res_typo["reasons"]))
        
        # Safe URL
        res_safe = analyze_url("https://www.google.com/search?q=streamlit")
        self.assertFalse(res_safe["is_suspicious"])

    def test_language_detector(self):
        # Devanagari Hindi
        self.assertEqual(detect_language("नमस्ते, आपका स्वागत है।"), "Hindi (Devanagari Script)")
        # Gujarati Script
        self.assertEqual(detect_language("કેમ છો? મજામાં?"), "Gujarati (Gujarati Script)")
        # Hinglish
        self.assertIn("Hinglish", detect_language("Apna otp batao jaldi se, account suspend ho jayega"))
        # Gujlish
        self.assertIn("Gujlish", detect_language("Rokan karo ane thodo faido thase tame free chho"))
        # English
        self.assertEqual(detect_language("Hi there, are we still meeting today at the cafe?"), "English")

    def test_ml_model_prediction(self):
        # Verify model file was written
        self.assertTrue(os.path.exists(config.MODEL_PATH))
        
        # Test clean load
        model = load_ml_model()
        self.assertIsNotNone(model)
        
        # Try inference
        res_scam = predict_scam_ml("Urgent work from home part time job earn money daily like videos")
        self.assertGreater(res_scam["ml_scam_score"], 40)
        self.assertEqual(res_scam["ml_category"], "Job Scam")
        
        res_safe = predict_scam_ml("Hello team, please review the document and send me your comments by 5 PM.")
        self.assertLess(res_safe["ml_scam_score"], 30)
        self.assertEqual(res_safe["ml_category"], "Safe")

    def test_db_logger_and_analytics(self):
        # Reset DB logs
        clear_logs()
        
        # Insert logs
        log_scan("Direct Text", "Shortlisted job work from home", 85, "Critical", "Job Scam", 90, "Test User")
        log_scan("URL Link", "http://bit.ly/claim-prize", 75, "High Risk", "Phishing", 85, "Test User")
        log_scan("Direct Text", "Hey friend, how are you?", 10, "Safe", "Safe", 95, "Test User")
        
        summary = get_analytics_summary()
        self.assertEqual(summary["total_scans"], 3)
        self.assertEqual(summary["high_risk_count"], 2)
        self.assertEqual(summary["category_distribution"]["Job Scam"], 1)
        self.assertEqual(summary["category_distribution"]["Safe"], 1)
        self.assertEqual(summary["input_type_distribution"]["Direct Text"], 2)
        
        # Verify trends
        self.assertGreater(len(summary["daily_trends"]), 0)

if __name__ == "__main__":
    unittest.main()
