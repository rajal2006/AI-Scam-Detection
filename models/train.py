import os
import sys
import joblib
import logging
import warnings
from pathlib import Path

# Add project root to path for imports
root_path = str(Path(__file__).resolve().parent.parent)
if root_path not in sys.path:
    sys.path.insert(0, root_path)

# Suppress sklearn/future warnings for clean console outputs
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold, cross_val_score
import config

logger = logging.getLogger("AIScamShield.TrainingPipeline")

# Multilingual training set for all scam categories and safe messages
TRAINING_DATA = [
    # --- Job Scam ---
    ("Urgent requirement for part time work from home. Daily earn 5000 to 10000 rupees. No experience required. Like YouTube videos and make money. Join Telegram: t.me/jobs39", "Job Scam"),
    ("Ghar baithe paise kamaye. Simple mobile tasks karke 3000 rs daily salary. Message this number on WhatsApp to start work from home today.", "Job Scam"),
    ("Dear candidate, your resume has been shortlisted for an online home-based assistant job. Weekly payout is 15000 INR. Register at our Telegram channel.", "Job Scam"),
    ("Ghare betha online kam karo ane paisa kamao. Darroj no paghar 2000-5000. Mobile thi video like karvana chhe. Join our WhatsApp group now.", "Job Scam"),
    ("રોજગાર ની ઉત્તમ તક. ઘરે બેઠા કામ કરો અને મહિને ૩૦૦૦૦ કમાવો. કોઈ અનુભવ ની જરૂર નથી.", "Job Scam"),
    ("घर बैठे काम करें। रोजाना 3000 कमाए। केवल यूट्यूब वीडियो लाइक करना है। टेलीग्राम पर संपर्क करें।", "Job Scam"),
    ("Double salary part-time job. Send message to start task today on Telegram.", "Job Scam"),
    ("You have been chosen for data entry job. Rs 2000 per sheet payout. No registration fees required.", "Job Scam"),
    ("Part time YouTube channel review work from home. Free registration, get paid instantly.", "Job Scam"),
    ("Earn money daily by completing simple tasks on Telegram. Easy work from home.", "Job Scam"),
    ("Part time job typing work at home. Daily payout. Register online today.", "Job Scam"),
    ("Ghar betha kam, typing work, daily salary Rs 1500, contact on WhatsApp.", "Job Scam"),
    ("Make quick money by completing easy tasks. Earn Rs.2000-5000 daily from your phone. Register now on Telegram.", "Job Scam"),
    ("YouTube video likes job. Part time, work from home. Daily salary Rs.3500. No qualifications needed.", "Job Scam"),

    # --- Investment Scam ---
    ("Double your money in just 24 hours. Invest 10,000 INR now and get 20,000 INR guaranteed return tomorrow. 100% risk free. Join VIP channel now.", "Investment Scam"),
    ("Paisa double scheme. Invest just 1000 rupees today and earn 500 daily compounding interest. Scheme closes in 2 hours, rush your deposit.", "Investment Scam"),
    ("Short term investment scheme: invest 5000 get 50000 in one week. Zero risk, 100% guarantee profit. DM for UPI deposit details.", "Investment Scam"),
    ("Rokan karo ane paisa double karo. 10 divas ma double return mali jashe. Koi jokhmi nathi. VIP chat link.", "Investment Scam"),
    ("પૈસા બમણા કરો. ૧૫ દિવસમાં મેળવો ડબલ રૂપિયા. વહેલા તે પહેલાં ધોરણે લિમિટેડ સીટો ઉપલબ્ધ છે.", "Investment Scam"),
    ("कम निवेश में बड़ा मुनाफा। आज ही 2000 रुपये लगाएं and हर सप्ताह 4000 रुपये का रिटर्न पाएं। बिना जोखिम की सुरक्षा।", "Investment Scam"),
    ("VIP share trading tips. 500% returns guaranteed within a week. Join VIP Telegram group.", "Investment Scam"),
    ("Earn huge profits by trading listed shares. Small fees, high daily compound return.", "Investment Scam"),
    ("Invest 5000 and get daily payout of 1000 for 12 consecutive months. Guaranteed scheme.", "Investment Scam"),
    ("Paisa double rokan offer. High returns guaranteed. No risk scheme.", "Investment Scam"),
    ("Guaranteed profit trading tips. Earn 10% daily returns on your capital. 100% risk free. Join VIP group.", "Investment Scam"),
    ("Paisa double scheme. Deposit 5000 via UPI and get 10000 back in 2 hours. Active slots left.", "Investment Scam"),

    # --- Crypto Scam ---
    ("Get free 1000 USDT! Claim your tokens now. Trust Wallet or MetaMask needed. Enter your seed phrase to claim your airdrop: shorturl.at/crypto", "Crypto Scam"),
    ("Earn 10% daily profit through bitcoin mining. Transfer 0.05 BTC to our wallet and get instant double payout. Join our binance cloud mining pool.", "Crypto Scam"),
    ("Attention: System has detected an incoming transfer of 1.25 BTC. Connect your trust wallet and enter your private key to receive the credit.", "Crypto Scam"),
    ("Crypto airdrop open now. Claim your free Solana tokens. Insert private key to initiate smart contract transfer.", "Crypto Scam"),
    ("બિટકોઈન માઈનિંગ સ્કીમ. દરરોજ કમાવો ૧૦% ક્રિપ્ટો નફો. આજે જ ડિપોઝિટ કરો.", "Crypto Scam"),
    ("MetaMask recovery phrase required to verify your decentralized wallet. Enter seed phrase.", "Crypto Scam"),
    ("Claim 100 BNB rewards immediately. Click link to import trust wallet seed words.", "Crypto Scam"),
    ("Free ethereum bonus transfer. Send 0.1 ETH to verify wallet and get 1 ETH back.", "Crypto Scam"),
    ("Claim free 500 USDT rewards. Enter your trust wallet private recovery seed phrase on our portal.", "Crypto Scam"),
    ("Bitcoin cloud mining contract. Guaranteed high returns daily. Send btc to our wallet to verify.", "Crypto Scam"),

    # --- Loan Scam ---
    ("Instant personal loan approved up to 5 Lakhs. Zero CIBIL score required. Low interest rates. Pay 2500 processing fees first for immediate disbursement.", "Loan Scam"),
    ("Emergency loan approved. Get money in your bank account in 5 minutes. No documentation or verification needed. Click here to pay advance file charges.", "Loan Scam"),
    ("Turant loan approval bina kisi document ke. Low interest rate aur aasan kishtein. Processing fees online bharein aur loan sanction karwayein.", "Loan Scam"),
    ("બિના ડોક્યુમેન્ટ લોન મંજૂર. ૨ મિનિટમાં ખાતામાં પૈસા. પ્રોસેસિંગ ફીસ પહેલા જમા કરાવો.", "Loan Scam"),
    ("बिना सिबिल स्कोर लोन पाएँ। तुरंत बैंक खाते में 2 लाख ट्रांसफर। बस प्रोसेसिंग शुल्क का भुगतान करें।", "Loan Scam"),
    ("Instant cash loan approved. Pay processing fees first to unlock the loan.", "Loan Scam"),
    ("Easy loans without background checks. Low interest rate. Transfer sanction fee first.", "Loan Scam"),
    ("Bina document loan sanction. Fast deposit to bank. Pay administrative fees.", "Loan Scam"),
    ("Instant cash loan. No documents or credit score checked. Transfer processing fee first to release loan.", "Loan Scam"),
    ("Emergency cash approved up to 3 Lakhs. Pay advance file charges online to sanction.", "Loan Scam"),

    # --- Lottery Scam ---
    ("Congratulations! Your mobile number won a lucky draw of 25 Lakh Rupees in KBC Lottery. To claim your prize money, call our lottery manager on WhatsApp.", "Lottery Scam"),
    ("Dear User, you have won 1 Crore Cash Prize from KBC Lucky Draw 2026. Send your bank details and 15,000 INR tax clearance fee to get your cheque.", "Lottery Scam"),
    ("Inaam jeeta hai aapne. 25 lakh KBC lottery lag gayi hai. Claim karne ke liye WhatsApp call karein aur processing charges bharo.", "Lottery Scam"),
    ("તમે ૨૫ લાખની લોટરી જીતી લીધી છે. ચેક લેવા માટે ટેક્સ ચાર્જ ચૂકવો. વોટ્સએપ પર કૉલ કરો.", "Lottery Scam"),
    ("लॉटरी विजेता! आपको मिलता है टाटा सफारी और 10 लाख नकद। फाइलिंग शुल्क जमा करने के लिए संपर्क करें।", "Lottery Scam"),
    ("You won lottery prize draw of 5 Lakhs. Contact support team to pay delivery tax.", "Lottery Scam"),
    ("Spin wheel winner of a brand new laptop. Pay custom registration fee to ship.", "Lottery Scam"),
    ("KBC lucky winner cheque dispatch. Pay tax charges to receive your reward.", "Lottery Scam"),
    ("You won a cash prize of 25 Lakhs in KBC Lottery lucky draw. Contact WhatsApp manager to pay tax fee.", "Lottery Scam"),
    ("Congratulations on winning the anniversary lottery. Send bank details and registration fee to claim.", "Lottery Scam"),

    # --- Romance Scam ---
    ("My dear, I am stuck at Delhi custom airport. They grabbed the gift parcel I sent you with gold and iPhone. Please transfer 35,000 INR custom clearance fees immediately.", "Romance Scam"),
    ("I love you so much and want to marry you. But my mother is in the ICU and I need urgent money for her heart operation. Please send me steam gift cards or wire cash.", "Romance Scam"),
    ("Hello sweet heart. I sent a suitcase with cash and presents for you, but the custom officer is demanding clearance duty. Please help me, I am alone at the terminal.", "Romance Scam"),
    ("Dear, my bank account is frozen and I need money for my flight ticket to meet you. Please help.", "Romance Scam"),
    ("Please send me some gift card codes to buy food. I will refund you once I arrive next week.", "Romance Scam"),
    ("Darling, the custom officer at Mumbai airport has stopped the iPhone package. Send 25000 Rs to release it.", "Romance Scam"),
    ("My sweet love, my sister is in the ICU and I need urgent money. Please send me gift cards or transfer cash.", "Romance Scam"),

    # --- Shopping Scam ---
    ("Clearance Sale: iPhone 15 Pro Max for just 2,999 INR! 95% off today only. Stock is running out fast. Order online now: http://cheap-iphone-store.xyz", "Shopping Scam"),
    ("Adidas Grand Anniversary: Free shoes for everyone! Click this link to spin the wheel and claim your free voucher worth 5000 INR.", "Shopping Scam"),
    ("Order delivery verification: Pay 10 rs to confirm your cash on delivery address, else your parcel will be canceled. Verify at: http://post-delivery.net", "Shopping Scam"),
    ("ધમાકા સેલ: બ્રાન્ડેડ શૂઝ અને ઘડિયાળો પર ૯૦% છૂટ. ફક્ત આજના દિવસ માટે.", "Shopping Scam"),
    ("Huge discount store clearance. Unbelievably cheap electronics on sale today.", "Shopping Scam"),
    ("Confirm COD delivery by depositing 20 rs verification fee. Link: post-ver.net", "Shopping Scam"),
    ("Clearance sale: brand new laptop for 3999 INR (90% off)! Order COD verification fee of 100 Rs now.", "Shopping Scam"),
    ("Click to spin the wheel and claim free shopping vouchers worth 10000. Pay shipping fee of 49 Rs.", "Shopping Scam"),

    # --- Phishing ---
    ("Alert: Your HDFC bank account is suspended due to pending PAN Card verification. Update your details within 24 hours to avoid closure: http://hdfc-kyc-verify.com", "Phishing"),
    ("Dear customer, your netbanking will be blocked today. Click this link to update your KYC details immediately: http://yono-sbi-login.secure.in/login.php", "Phishing"),
    ("Your Netflix account has been suspended due to payment failure. Update your billing address and credit card info here: http://netflx-account-renew.com", "Phishing"),
    ("SBI account block hone se bachayein. Apna KYC update karne ke liye niche diye link par click karein aur verify karein.", "Phishing"),
    ("તમારું બેંક એકાઉન્ટ બ્લોક થઇ ગયું છે. તેને ચાલુ કરવા માટે આ લિંક પર કેવાયસી અપડેટ કરો.", "Phishing"),
    ("प्रिय ग्राहक, आपका एसबीआई योनो अकाउंट ब्लॉक हो गया है। एक्टिवेट करने के लिए पैन कार्ड लिंक करें।", "Phishing"),
    ("Verify your netbanking user profile using the URL below to activate access.", "Phishing"),
    ("Dear customer, your bank ATM card is blocked. Click portal to verify PIN and PAN card.", "Phishing"),
    ("Your gas connection will be disconnected today. Pay pending bill at: http://gas-payment-renew.xyz", "Phishing"),
    ("Update your Aadhaar card details online now to avoid pension suspension.", "Phishing"),
    ("Alert: Your bank netbanking account is suspended. Update your PAN card details immediately to link.", "Phishing"),
    ("KYC verification pending: Link your Aadhaar card now to avoid account closure: banking-kyc-verify.com", "Phishing"),

    # --- OTP / Account Takeover Scam ---
    ("Important security alert: We detected a suspicious login attempt on your account. Share the 6-digit OTP code sent to your phone with our executive to secure it.", "OTP / Account Takeover Scam"),
    ("Apne account ko verification check ke liye secure karein. Aapke mobile par aaya hua OTP batao taaki transactions verify ho sakein.", "OTP / Account Takeover Scam"),
    ("તમારા મોબાઈલમાં આવેલ ઓટીપી નંબર શેર કરો જેથી કરીને ગેસ સબસિડી ચાલુ થઇ શકે.", "OTP / Account Takeover Scam"),
    ("Share OTP code to confirm your gas booking discount immediately.", "OTP / Account Takeover Scam"),
    ("Tell me the OTP sent to your phone to update your address delivery.", "OTP / Account Takeover Scam"),
    ("Forward me the verification code you received.", "OTP / Account Takeover Scam"),
    ("Can you please share the OTP I accidentally sent to your number?", "OTP / Account Takeover Scam"),
    ("We detected a login from a different device. Please tell me the OTP sent to your phone to confirm it.", "OTP / Account Takeover Scam"),
    ("Share the 6-digit verification code you received to confirm your order delivery refund.", "OTP / Account Takeover Scam"),

    # --- UPI Scam ---
    ("You received a scratch card bonus of 500 INR! To claim this cashback, scan this QR code on Google Pay and enter your UPI PIN. The money will credit.", "UPI Scam"),
    ("Scan QR code to receive money in your Paytm wallet. Enter your UPI PIN to sanction the incoming transfer of 2000 INR. Scanning QR receives cash.", "UPI Scam"),
    ("GPay cashback offer. Scan code, put UPI PIN and collect reward money.", "UPI Scam"),
    ("upi pin daalo aur cashback collect karo. Google Pay scratch card mila hai.", "UPI Scam"),
    ("યુપીઆઈ પીન ટાઈપ કરો અને તમારા ખાતામાં ૫૦૦૦ રૂપિયા મેળવો. ક્યુઆર કોડ સ્કેન કરો.", "UPI Scam"),
    ("Scan QR code, enter UPI PIN and collect rewards in GPay wallet.", "UPI Scam"),
    ("Scratch card cash claim. Scan the code to receive money in bank account.", "UPI Scam"),
    ("Scan this QR code and type your UPI PIN to claim your scratch card cashback.", "UPI Scam"),
    ("Double cash cashback! Enter your UPI PIN to receive money in your Google Pay account.", "UPI Scam"),

    # --- Customer Support Scam ---
    ("Dear User, we detected a virus in your system. Call Microsoft Tech Support Helpline toll-free immediately: 1-800-410-0987 for assistance.", "Customer Support Scam"),
    ("SBI bank customer care executive calling. We need to upgrade your card. Install AnyDesk application from Play Store and share the desk ID number.", "Customer Support Scam"),
    ("Having issues with Google Pay transaction? Install TeamViewer QuickSupport application to resolve it with our helpdesk team online.", "Customer Support Scam"),
    ("કોઈપણ પ્રોબ્લેમ માટે બેંક કસ્ટમર કેર નો સંપર્ક કરો. AnyDesk એપ ડાઉનલોડ કરો.", "Customer Support Scam"),
    ("Helpline executive calling, please download TeamViewer desk sharing to check transaction status.", "Customer Support Scam"),
    ("Install AnyDesk to configure your mobile banking application profile securely.", "Customer Support Scam"),
    ("Microsoft helpdesk calling: To remove malware from your PC, download AnyDesk app and share user ID.", "Customer Support Scam"),
    ("Having issues with your transactions? Install TeamViewer and share your screen with support.", "Customer Support Scam"),

    # --- Social Media Scam ---
    ("Get 10,000 Instagram followers for just 99 INR. 100% real accounts, instant delivery. Increase your profile reach today: http://instagram-booster.xyz", "Social Media Scam"),
    ("We can recover your hacked Instagram or Facebook profile in 30 minutes. 100% success rate. DM us now. Administration fee required.", "Social Media Scam"),
    ("Get your profile verified with a blue tick badge. Apply now for free blue badge verification. Fee of 500 rs required.", "Social Media Scam"),
    ("Increase your social reach: 10000 followers and blue badge verified check for 199 Rs.", "Social Media Scam"),
    ("Recover any hacked or disabled Instagram profile instantly. Direct message us. Small fee applies.", "Social Media Scam"),

    # --- Safe (Benign Messages) ---
    ("Hey! Are you coming to the college library today? We need to work on the computer network assignment together.", "Safe"),
    ("Happy Birthday Amit! Have a fantastic day and a wonderful year ahead. Let me know when we are celebrating.", "Safe"),
    ("Please find attached the monthly sales forecast report for your review. Let me know if you need any adjustments.", "Safe"),
    ("Hi Mom, I will be late coming home tonight. Don't wait for dinner, I will grab some food with friends on the way.", "Safe"),
    ("Dear applicant, thank you for submitting your application to Google. We have scheduled your interview at our office on Friday.", "Safe"),
    ("Let's meet at 5 PM for coffee in the cafeteria. We can review the project milestones then.", "Safe"),
    ("Your OTP for login to your personal Amazon account is 492038. Do not share this code with anyone.", "Safe"),
    ("Can you please send me the recipe for the Gujarati Dhokla? I tried making it but it didn't turn out well.", "Safe"),
    ("Kem chho? Mane thodi help joiyye chhe tamari. Bapor pachi free chho tame?", "Safe"),
    ("કાલે સવારે આપણે મીટિંગ રાખેલી છે. સમયસર ઓફિસે પહોંચી જજો.", "Safe"),
    ("प्रिय राहुल, क्या आप आज शाम को फुटबॉल खेलने आ रहे हैं? मुझे अवश्य बताएं।", "Safe"),
    ("Yes, I will transfer the pending amount to your bank account using GPay tonight. Please send your bank details.", "Safe"),
    ("Hello team, please review the document and send me your comments by 5 PM.", "Safe"),
    ("Did you finish reading the book I lent you last week? Let know what you think.", "Safe"),
    ("Dear customer, your bill of INR 1499 is generated for mobile number 9876543210. Pay by due date to avoid late fees.", "Safe"),
    ("Your order has been shipped and will be delivered by Amazon today. You can track your shipment on the official app.", "Safe"),
    ("Please remember to buy milk and bread on your way home tonight. Thank you!", "Safe"),
    ("Can you send me the Zoom link for the project alignment meeting scheduled for tomorrow morning?", "Safe"),
    ("Hi Professor, could you please clarify the grading rubric for the final semester assignment?", "Safe"),
    ("Your appointment with Dr. Sharma is confirmed for Tuesday at 4:30 PM. Please arrive 10 minutes early.", "Safe"),
    ("Good morning! Just wanted to wish you a wonderful and productive week ahead.", "Safe"),
    ("Please review the draft design proposal and let me know if you have any feedback before we send it to the client.", "Safe"),
    ("Can we reschedule our lunch plan to Friday? Something urgent came up at work today.", "Safe"),
    ("Thank you for your generous contribution to the community education fund. Your receipt is attached.", "Safe"),
    ("Hey, did you see the new movie that released yesterday? Let's plan to watch it this weekend.", "Safe"),
    ("Hello, I am sending the document for your signature. Please sign and return it to me at your easiest convenience.", "Safe"),
    ("Hi, I just wanted to check if you have received the package I sent you last Wednesday.", "Safe"),
    ("Dear member, your subscription will auto-renew next month. No action is required if you wish to continue.", "Safe"),
    ("Hey, are you free for a quick call to discuss the itinerary for our trip next month?", "Safe"),
    ("Your flight check-in is now open. Please select your seats and download your boarding pass.", "Safe"),
    ("Hi, the office will remain closed tomorrow on account of the public holiday. Enjoy your long weekend!", "Safe"),
    ("Can you please share the contact details of the vendor who handled the catering last time?", "Safe"),
    ("The weather is really nice today. Let's go for a walk in the evening if you have some free time.", "Safe"),
    ("Hello, your car servicing is completed. You can collect your vehicle anytime before 7 PM today.", "Safe"),
    ("Please check the train timings for tomorrow. The ticket is booked.", "Safe"),
    ("Hi, are you attending the birthday party this weekend?", "Safe"),
    ("Can you send the draft proposal for client feedback?", "Safe"),
    ("Your order has been packed and will leave our facility today.", "Safe"),
    ("Happy Diwali to you and your family! Have a great and prosperous year ahead.", "Safe"),
    ("Dear student, the exam schedule has been updated. Please download the revised date sheet.", "Safe"),
    ("Hello, I will be out of office today. For urgent queries, please contact my team leader.", "Safe"),
    ("Let's plan a picnic this Sunday. Weather is looking nice.", "Safe"),
    ("Your OTP for phone verification is 902813.", "Safe"),
    ("Your login code is 834291. Do not share this code with anyone.", "Safe"),
    ("DO NOT SHARE: 102938 is your verification code. If someone asks for this over a call, they are trying to steal your account. OTP: 102938", "Safe"),
    ("Please verify the delivery address for your order.", "Safe"),
    ("We are planning a review meeting for next Monday. Please bring your slide deck.", "Safe"),
    ("Good evening, can we confirm the schedule for the next week release checks?", "Safe"),
    ("Hi, I received the flowers you sent. Thank you so much for the thoughtful gift!", "Safe"),
    ("Let know if you need any help setting up the new desktop monitor in the meeting room.", "Safe"),
    ("Dear guest, your table reservation at the restaurant is confirmed for 8 PM tonight.", "Safe"),
    ("The library book you borrowed is due for return by next Wednesday.", "Safe"),

    # --- Job Scam (Additional) ---
    ("Earn money by rating hotels on Google Maps. Earn 5000 Rs daily. Contact on Telegram.", "Job Scam"),
    ("Ghar baithe job, online typing, weekly salary 10000 INR. Free registration.", "Job Scam"),
    ("ગુજરાતી ટાઇપિંગ કામ, ઘરે બેઠા કમાવો દરરોજ ૨૦૦૦ રૂપિયા. વોટ્સએપ પર સંપર્ક કરો.", "Job Scam"),
    ("पार्ट टाइम जॉब, यूट्यूब वीडियो लाइक करें और पैसे कमाएं। कोई निवेश नहीं।", "Job Scam"),
    ("Part time home based online jobs. Rs.1500 to Rs.4000 daily payment. No registration fees.", "Job Scam"),
    
    # --- Investment Scam (Additional) ---
    ("Earn 20% interest daily on your investment. Scheme ends soon, deposit now via GPay.", "Investment Scam"),
    ("Double your income in 7 days! Trustworthy scheme with zero risk. DM for info.", "Investment Scam"),
    ("મોટું રિટર્ન મેળવો. રોકાણ કરો અને દર મહિને વ્યાજ મેળવો. ૧૦૦% સેફ.", "Investment Scam"),
    ("शेयर बाजार में निवेश करें और प्रतिदिन 10% मुनाफा कमाएं। विप टेलीग्राम ग्रुप।", "Investment Scam"),
    ("Double your deposit in 24 hours. Invest 2000 and get 4000 cash back instantly. Secure VIP scheme.", "Investment Scam"),
    
    # --- Crypto Scam (Additional) ---
    ("Claim 500 USDT now! Connect your wallet and enter recovery phrase to authenticate.", "Crypto Scam"),
    ("Bitcoin double scheme. Send 0.01 BTC and receive 0.02 BTC instantly. Legitimate cloud mining.", "Crypto Scam"),
    ("નવા ક્રિપ્ટો કોઈન જીતો. વોલેટ કનેક્ટ કરો અને તમારી સીડ કી દાખલ કરો.", "Crypto Scam"),
    ("फ्री क्रिप्टो एयरड्रॉप। अपने ट्रस्ट वॉलेट की रिकवरी की दर्ज करें।", "Crypto Scam"),
    ("Connect your MetaMask or Trust Wallet and type seed words to claim your rewards.", "Crypto Scam"),
    
    # --- Loan Scam (Additional) ---
    ("Get low interest loan up to 10 lakhs in 5 minutes. Bad CIBIL score accepted. Register now.", "Loan Scam"),
    ("Bina security loan. 100% approved. Pay file approval charges of 1500 INR first.", "Loan Scam"),
    ("ઓછા વ્યાજે ત્વરિત લોન. પ્રોસેસિંગ ફી પેલા ભરો અને ૨ લાખ મેળવો.", "Loan Scam"),
    ("बिना गारंटी लोन पाएं। तुरंत बैंक ट्रांसफर। बस 2000 रुपये फाइल चार्ज जमा करें।", "Loan Scam"),
    ("Urgent loans without credit checks. Minimum documentation. Send processing fee now to disburse.", "Loan Scam"),
    
    # --- Lottery Scam (Additional) ---
    ("You won 10 Lakh cash prize in Diwali lucky draw. Pay custom handling charges to claim.", "Lottery Scam"),
    ("KBC Head Office calling. Aapka number 25 lakh lottery jeet chuka hai. WhatsApp call karein.", "Lottery Scam"),
    ("તમને ૨૫ લાખની લોટરી લાગી છે. સરકારી ટેક્સ ૧૦૦૦૦ પહેલા જમા કરાવો.", "Lottery Scam"),
    ("दिवाली धमाका लॉटरी! आपने जीता है टाटा नेक्सन। डिलीवरी चार्ज पहले भरें।", "Lottery Scam"),
    ("Congratulations! You are the winner of 25 Lakhs cash prize in KBC lucky draw. DM to claim.", "Lottery Scam"),
    
    # --- Romance Scam (Additional) ---
    ("I sent you a diamond necklace and gold watch from London. The custom officer caught it. Pay 30k clearance.", "Romance Scam"),
    ("Honey, my mom is sick and needs immediate operation. I need 20,000 INR urgently. Please wire it.", "Romance Scam"),
    ("પ્રિય, હું એરપોર્ટ પર કસ્ટમ ઓફિસર સાથે અટવાયો છું. મહેરબાની કરીને દંડની રકમ મોકલો.", "Romance Scam"),
    ("मेरी प्यारी, मेरी बहन अस्पताल में है। मुझे तुरंत कुछ पैसों की जरूरत है, प्लीज मदद करो।", "Romance Scam"),
    ("I love you. I want to send you some gold gifts, but custom clearance charge of 15000 is required.", "Romance Scam"),
    
    # --- Shopping Scam (Additional) ---
    ("Super Sale: iPhone 15 only Rs. 1,999! Limited stock, buy now: cheap-deals.online", "Shopping Scam"),
    ("Spin to win free Adidas shoes! Pay delivery charge of 99 INR to ship your prize.", "Shopping Scam"),
    ("૯૦% ડિસ્કાઉન્ટ સેલ. બ્રાન્ડેડ ઘડિયાળો માત્ર ૪૯૯ માં. ઓર્ડર કરો આજે જ.", "Shopping Scam"),
    ("धमाका सेल: नाइके के जूते मात्र 299 रुपये में। अभी ऑर्डर करने के लिए क्लिक करें।", "Shopping Scam"),
    ("Clearance offer: 95% discount on all branded apparel. Shop today at our low price store.", "Shopping Scam"),
    
    # --- Phishing (Additional) ---
    ("Urgent KYC update required for your SBI account. Click here to verify your netbanking details: sbi-kyc-check.com", "Phishing"),
    ("Your SIM card will block today. Update PAN card and Aadhaar card at: sim-verify.net", "Phishing"),
    ("બેંક એકાઉન્ટ કેવાયસી પેન્ડિંગ છે. આ લિંક પર ક્લિક કરી અપડેટ કરો.", "Phishing"),
    ("आपका बैंक खाता ब्लॉक कर दिया गया है। पुनः सक्रिय करने के लिए अपना आधार लिंक करें।", "Phishing"),
    ("Dear HDFC customer, your mobile banking app access is suspended. Verify credentials at: hdfc-net-login.com", "Phishing"),
    
    # --- OTP / Account Takeover Scam (Additional) ---
    ("Please tell me the verification code sent to your mobile to verify your gas booking connection.", "OTP / Account Takeover Scam"),
    ("Share the OTP code you received to cancel the pending transaction on your credit card.", "OTP / Account Takeover Scam"),
    ("તમારા નંબર પર આવેલ ૬ આંકડાનો ઓટીપી જણાવો જેથી ગેસ કનેક્શન ચાલુ કરી શકાય.", "OTP / Account Takeover Scam"),
    ("अपने मोबाइल पर आया हुआ 6 अंकों का ओटीपी साझा करें ताकि आपका खाता सुरक्षित हो सके.", "OTP / Account Takeover Scam"),
    ("We sent a verification code to your phone by mistake. Can you tell me the code to fix it?", "OTP / Account Takeover Scam"),
    
    # --- UPI Scam (Additional) ---
    ("Scan this QR code to claim your GPay scratch card reward. Put your UPI PIN to credit.", "UPI Scam"),
    ("Paytm cashback credit: scan QR code and type UPI PIN to receive money in bank account.", "UPI Scam"),
    ("ક્યુઆર કોડ સ્કેન કરો અને યુપીઆઈ પીન દાખલ કરો જેથી પૈસા તમારા ખાતામાં જમા થાય.", "UPI Scam"),
    ("गूगल पे स्क्रैच कार्ड! कैशबैक पाने के लिए क्यूआर કોડ સ્કેન કરો અને યુપીઆઈ પીન દાખલ કરો.", "UPI Scam"),
    ("Scan the Paytm QR code to claim 1000 cashback reward. Enter your UPI PIN to confirm.", "UPI Scam"),
    
    # --- Customer Support Scam (Additional) ---
    ("Microsoft technical support: download AnyDesk app to scan your computer for virus.", "Customer Support Scam"),
    ("Bank helpline support: install TeamViewer application and share your desktop desk ID.", "Customer Support Scam"),
    ("ટેક્નિકલ સપોર્ટ ટીમ: તમારા કમ્પ્યુટરમાંથી વાયરસ કાઢવા માટે AnyDesk એપ ઇન્સ્ટોલ કરો.", "Customer Support Scam"),
    ("बैंक हेल्पलाइन: अपना खाता अपडेट करने के लिए एनीडेस्क ऐप डाउनलोड करें और आईडी बताएं।", "Customer Support Scam"),
    ("Contact customer service support. Please download TeamViewer app and share desk id to debug transaction.", "Customer Support Scam"),
    
    # --- Social Media Scam (Additional) ---
    ("Buy 5000 active Instagram followers and likes for 49 INR. Instant transfer.", "Social Media Scam"),
    ("Get your Facebook account verified with blue tick mark. Pay processing fees of 999.", "Social Media Scam"),
    ("ઇન્સ્ટાગ્રામ ફોલોઅર્સ વધારો માત્ર ૯૯ રૂપિયામાં. ૧૦૦% સાચા એકાઉન્ટ.", "Social Media Scam"),
    ("इंस्टाग्राम पर ब्लू टिक पाएं। केवल 500 रुपये वेरिफिकेशन शुल्क। अभी आवेदन करें।", "Social Media Scam"),
    ("Boost your TikTok or Twitter followers. Cheap packages starting at $2. 100% active followers.", "Social Media Scam"),
    
    # --- Safe (Additional) ---
    ("Can you send the PDF report of the project milestones? I need to review it before the meeting.", "Safe"),
    ("Happy Anniversary to both of you! Wish you a wonderful life together ahead.", "Safe"),
    ("Hey, please pick up some vegetables while returning from work today. Thanks.", "Safe"),
    ("તમારો ગેસ સિલિન્ડર બુક થઇ ગયો છે. ડિલિવરી માટે કોઈ ઓટીપી આપવાની જરૂર નથી.", "Safe"),
    ("आपका पार्सल आज डिलीवर हो जाएगा। डिलीवरी बॉय का नंबर: 9876543210.", "Safe"),
    ("Please let me know if you are coming to office tomorrow or working from home.", "Safe"),
    ("Meeting link for tomorrow's standup is updated in the calendar invite.", "Safe"),
    ("Congratulations on your new job promotion! Well deserved success.", "Safe"),
    ("Did you complete the draft presentation? Let me know if you need help with formatting.", "Safe"),
    ("Your train booking is confirmed. Seat details and itinerary are attached.", "Safe"),
    ("Your gas booking update is successful. No OTP needs to be shared with the delivery agent.", "Safe"),
    ("Please do not share your OTP with anyone. Our customer care will never ask for it.", "Safe"),
]

def train_and_save_model() -> None:
    """
    Trains a tuned TF-IDF + Logistic Regression pipeline
    on the multilingual dataset, runs cross-validation, and saves it.
    """
    logger.info("Initializing ML model training...")
    
    # Unpack samples
    texts, labels = zip(*TRAINING_DATA)
    
    # Define vectorization & classification pipeline (Char-wb TF-IDF + Logistic Regression C=20)
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            lowercase=True,
            analyzer='char_wb',
            ngram_range=(3, 5),
            sublinear_tf=True,
            min_df=1
        )),
        ('clf', LogisticRegression(
            class_weight='balanced',
            C=20.0,
            max_iter=1000,
            solver='lbfgs'
        ))
    ])
    
    # Binary classification pipeline
    binary_pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            lowercase=True,
            analyzer='char_wb',
            ngram_range=(3, 5),
            sublinear_tf=True,
            min_df=1
        )),
        ('clf', LogisticRegression(
            class_weight='balanced',
            C=20.0,
            max_iter=1000,
            solver='lbfgs'
        ))
    ])
    
    # Stratified 3-Fold Cross Validation for Multiclass
    logger.info("Running Stratified 3-Fold Multiclass Cross-Validation...")
    try:
        cv_multi = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        scores_multi = cross_val_score(pipeline, texts, labels, cv=cv_multi, scoring='accuracy')
        mean_acc_multi = scores_multi.mean() * 100
        logger.info(f"Multiclass CV Accuracies: {[round(s*100, 2) for s in scores_multi]}")
        logger.info(f"==> Multiclass Mean Accuracy: {mean_acc_multi:.2f}%")
    except Exception as e:
        logger.error(f"Multiclass CV calculation encountered error: {e}")
        
    # Stratified 5-Fold Cross Validation for Binary (Safe vs Scam)
    logger.info("Running Stratified 5-Fold Binary (Safe vs Scam) Cross-Validation...")
    try:
        binary_labels = ["Safe" if l == "Safe" else "Scam" for l in labels]
        cv_bin = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scores_bin = cross_val_score(binary_pipeline, texts, binary_labels, cv=cv_bin, scoring='accuracy')
        mean_acc_bin = scores_bin.mean() * 100
        logger.info(f"Binary Detection CV Accuracies: {[round(s*100, 2) for s in scores_bin]}")
        logger.info(f"==> Mean Binary Detection Accuracy (Safe vs Scam): {mean_acc_bin:.2f}%")
    except Exception as e:
        logger.error(f"Binary CV calculation encountered error: {e}")
    
    # Fit full model
    logger.info(f"Fitting final pipeline on {len(texts)} samples across {len(set(labels))} classes...")
    pipeline.fit(texts, labels)
    
    # Ensure model folder exists
    model_path = config.MODEL_PATH
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Save model
    joblib.dump(pipeline, model_path)
    logger.info(f"Trained ML model successfully saved to: {model_path}")

if __name__ == "__main__":
    # Setup simple logging to stream if running manually
    logging.basicConfig(level=logging.INFO)
    train_and_save_model()
