import sys
from pathlib import Path
import numpy as np

# Add project root to path
root_path = "/Users/rajalgadhvi/AI Scam Detection"
if root_path not in sys.path:
    sys.path.insert(0, root_path)

from backend.engine import analyze_suspicious_input

# 30 Test Cases (10 Low Risk, 10 Medium Risk, 10 High Risk)
TEST_CASES = [
    # --- Low Risk (10) ---
    ("Your WhatsApp verification code is 483921. Do not share this code with anyone.", "Low Risk"),
    ("Your bank account ending in 1234 has been credited with INR 5,000 on 2026-05-31.", "Low Risk"),
    ("Reminder: The project sync meeting is scheduled for tomorrow at 10 AM. Here is the link: zoom.us/j/12345", "Low Risk"),
    ("Your order has been shipped via Blue Dart and will be delivered by end of day today.", "Low Risk"),
    ("Hey! Are you coming to the college library today? We need to work on the network assignment.", "Low Risk"),
    ("Happy Birthday Amit! Have a fantastic day and a wonderful year ahead.", "Low Risk"),
    ("Dear customer, your bill of INR 1,499 is generated for mobile number 9876543210. Pay by due date.", "Low Risk"),
    ("Please find attached the monthly sales forecast report for your review.", "Low Risk"),
    ("Your appointment with Dr. Sharma is confirmed for Tuesday at 4:30 PM.", "Low Risk"),
    ("Can you send the draft proposal for client feedback?", "Low Risk"),

    # --- Suspicious / Medium Risk (10) ---
    ("Hurry up! Invest now in this new scheme to double your money. Offer valid for today only!", "Suspicious / Medium Risk"),
    ("Congratulations! You have been selected as the KBC lottery lucky draw winner of 25 Lakhs. Click here to check the details.", "Suspicious / Medium Risk"),
    ("Special clearance sale: Brand new shoes and watches at 90% off today only! Buy now before stock runs out.", "Suspicious / Medium Risk"),
    ("Hey dear, I need your help. I sent you a gift box but it got stuck at customs. Can you check this unknown website link to track it: customs-tracker.net?", "Suspicious / Medium Risk"),
    ("We are offering easy personal loans with low interest rates and no documentation. Invest in your business today.", "Suspicious / Medium Risk"),
    ("Hurry! Get 10,000 active Instagram followers for just 99 INR today only: social-boost.xyz", "Suspicious / Medium Risk"),
    ("My sweet friend, my sister is in the hospital and needs money urgently. Can you please help me?", "Suspicious / Medium Risk"),
    ("Claim your free Solana tokens airdrop now by visiting this link.", "Suspicious / Medium Risk"),
    ("Spin the wheel and claim free shopping vouchers worth 10000. Limited entries left.", "Suspicious / Medium Risk"),
    ("Part-time job work from home: Earn 3000 rs daily by doing simple mobile tasks. Join Telegram group.", "Suspicious / Medium Risk"),

    # --- High Risk (10) ---
    ("Important security alert: We detected a suspicious login on your account. Share the 6-digit OTP code sent to your phone to secure it.", "High Risk"),
    ("Please verify your netbanking username and password immediately to unlock your frozen account: bank-login-update.com", "High Risk"),
    ("Your HDFC bank account is suspended due to pending PAN Card verification. Update KYC immediately here to avoid permanent block.", "High Risk"),
    ("This is customer support executive. Please download AnyDesk application from play store and share the ID code to fix your billing error.", "High Risk"),
    ("Google Pay cashback reward! To receive 500 INR, scan this QR code and type in your UPI PIN.", "High Risk"),
    ("Forward me the verification code you received on your mobile to verify your transaction.", "High Risk"),
    ("Urgent: Your SIM card will be deactivated within 24 hours. Click link to verify your Aadhaar card details: sim-verify.com", "High Risk"),
    ("This is the police department calling. You are under investigation for illegal activities. Do not tell anyone and transfer 50k to our safe ledger now.", "High Risk"),
    ("Hello, I accidentally sent my login code to your number. Can you please text me that OTP?", "High Risk"),
    ("Your netbanking profile has expired. To renew access, input your card number, CVV, and ATM PIN on our secure portal: banking-secure.net", "High Risk")
]

def run_validation():
    print("="*60)
    print("AI SCAM SHIELD RISK CLASSIFICATION PIPELINE VALIDATION")
    print("="*60)
    
    y_true = []
    y_pred = []
    scores = []
    
    for idx, (text, true_risk) in enumerate(TEST_CASES):
        result = analyze_suspicious_input(text)
        pred_risk = result["risk_level"]
        score = result["scam_score"]
        
        y_true.append(true_risk)
        y_pred.append(pred_risk)
        scores.append(score)
        
        print(f"[{idx+1:02d}] True: {true_risk:<25} | Pred: {pred_risk:<25} | Score: {score:>3} | Text: {text[:55]}...")

    print("\n" + "="*60)
    print("CLASS DISTRIBUTION ANALYSIS")
    print("="*60)
    
    unique_true, counts_true = np.unique(y_true, return_counts=True)
    unique_pred, counts_pred = np.unique(y_pred, return_counts=True)
    
    true_dist = dict(zip(unique_true, counts_true))
    pred_dist = dict(zip(unique_pred, counts_pred))
    
    print("Ground Truth Distribution:")
    for k, v in true_dist.items():
        print(f"  - {k:<25}: {v} samples ({v/len(y_true)*100:.1f}%)")
        
    print("\nPredicted Distribution:")
    for k in ["Low Risk", "Suspicious / Medium Risk", "High Risk"]:
        v = pred_dist.get(k, 0)
        print(f"  - {k:<25}: {v} samples ({v/len(y_pred)*100:.1f}%)")

    print("\n" + "="*60)
    print("CONFUSION MATRIX")
    print("="*60)
    
    classes = ["Low Risk", "Suspicious / Medium Risk", "High Risk"]
    matrix = np.zeros((3, 3), dtype=int)
    
    for t, p in zip(y_true, y_pred):
        t_idx = classes.index(t)
        p_idx = classes.index(p)
        matrix[t_idx, p_idx] += 1
        
    # Print Confusion Matrix nicely
    print(f"{'True \\ Pred':<25} | {'Low Risk':^10} | {'Suspicious':^10} | {'High Risk':^10}")
    print("-" * 65)
    for i, label in enumerate(classes):
        print(f"{label:<25} | {matrix[i, 0]:^10} | {matrix[i, 1]:^10} | {matrix[i, 2]:^10}")

    accuracy = np.mean(np.array(y_true) == np.array(y_pred)) * 100
    print(f"\nOverall Pipeline Risk Classification Accuracy: {accuracy:.2f}%")

    print("\n" + "="*60)
    print("THRESHOLD OPTIMIZATION ANALYSIS")
    print("="*60)
    
    low_scores = [scores[i] for i in range(len(scores)) if y_true[i] == "Low Risk"]
    med_scores = [scores[i] for i in range(len(scores)) if y_true[i] == "Suspicious / Medium Risk"]
    high_scores = [scores[i] for i in range(len(scores)) if y_true[i] == "High Risk"]
    
    print(f"Low Risk Scores   - Min: {min(low_scores):>3}, Max: {max(low_scores):>3}, Mean: {np.mean(low_scores):.1f}")
    print(f"Medium Risk Scores- Min: {min(med_scores):>3}, Max: {max(med_scores):>3}, Mean: {np.mean(med_scores):.1f}")
    print(f"High Risk Scores  - Min: {min(high_scores):>3}, Max: {max(high_scores):>3}, Mean: {np.mean(high_scores):.1f}")
    
    print("\nSuggested Final Thresholds:")
    print("  - Low Risk Category Threshold           : Score < 30")
    print("  - Suspicious / Medium Risk Threshold    : 30 <= Score < 65")
    print("  - High Risk Category Threshold          : Score >= 65")
    print("="*60)

if __name__ == "__main__":
    run_validation()
