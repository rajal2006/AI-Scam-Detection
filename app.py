import streamlit as st
import os
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image



# Import configurations & helpers
import config
from backend.engine import analyze_suspicious_input
from backend.ocr_engine import extract_text_from_image
from backend.url_analyzer import analyze_url
from utils.db_helper import init_db, log_scan, get_analytics_summary, get_recent_logs, clear_logs
from utils.language import detect_language
from utils.voice import transcribe_audio, VOICE_DEMO_PRESETS

# Page Configuration
st.set_page_config(
    page_title="AI Scam Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database and train/load ML model on startup
init_db()
from backend.ml_model import load_ml_model
load_ml_model()

# Load custom CSS styles
css_path = os.path.join(config.ASSETS_DIR, "style.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
else:
    st.warning("CSS style file could not be loaded. Running with default styles.")

# Main Application Title
st.markdown("""
    <div style='text-align: center; padding: 20px 0px 10px 0px;'>
        <h1 class='gradient-text' style='font-size: 3em; margin-bottom: 0px;'>🛡️ AI SCAM SHIELD</h1>
        <p style='color: #8a9fc4; font-size: 1.2em; font-weight: 300;'>Intelligent Real-Time Anti-Fraud & Phishing Analytics</p>
    </div>
""", unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.markdown("""
    <div style='text-align: center; margin-bottom: 20px;'>
        <span class='pulse-dot'></span> <b style='color: #00f0ff; font-family: "Orbitron";'>SHIELD STATUS: ACTIVE</b>
    </div>
""", unsafe_allow_html=True)

st.sidebar.header("🔑 Model Settings")
if config.GEMINI_API_KEY:
    st.sidebar.success("✅ Gemini API securely loaded from environment (.env).")
else:
    st.sidebar.info("💡 Running in local engine mode (Rule Engine + Scikit-learn Classifier). Configure your `GEMINI_API_KEY` in the `.env` file to unlock deep LLM reasoning.")

st.sidebar.markdown("---")
st.sidebar.header("🛡️ Quick Cyber Tips")
st.sidebar.markdown("""
- **Verify QR Codes**: Scanning a QR code is only for **paying** money, never for **receiving** it.
- **OTPs are Private**: Bank staff will never call you to request an OTP.
- **Verify Job Offers**: Real companies do not charge processing or training fees.
- **Check URLs**: Double check that the website URL matches the official brand site exactly.
""")

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Diagnostics")
if st.sidebar.button("Clear Scan History Logs", type="secondary"):
    clear_logs()
    st.sidebar.success("Database logs wiped.")
    st.rerun()

# Tabs
tab1, tab2, tab3 = st.tabs(["🔍 Scam Scan", "📊 Admin Analytics", "📘 About & FAQ"])

# TAB 1: SCAM SCANNER
with tab1:
    st.markdown("""
        <div class='cyber-card'>
            <h3>🚨 Suspicious Message Analyzer</h3>
            <p>Upload files or paste texts received from SMS, WhatsApp, Emails, Instagram, or Telegram. Our hybrid engine will check for manipulation tactics, phishing links, and fraud signals.</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Input categories columns
    input_mode = st.radio(
        "Select Input Channel Type:",
        ["Direct Text Copy-Paste", "Chat Conversation Log", "WhatsApp Export File (.txt)", "Screenshot Upload (OCR)", "URL Link Analyzer", "Spoken Voice Audio"],
        horizontal=True
    )
    
    analyzed_text = ""
    input_channel_label = "Direct Text"
    
    # 1. Direct Copy-Paste Text
    if input_mode == "Direct Text Copy-Paste":
        input_channel_label = "Direct Text"
        analyzed_text = st.text_area(
            "Paste the suspicious message content here:",
            placeholder="Example: Dear customer, you have won Rs 25 Lakhs lottery in KBC lucky draw. Contact manager Mr. Kumar on WhatsApp at 9876543210 to claim...",
            height=150
        )
        
        # Preset buttons for easy testing
        st.markdown("**Sample Presets for quick evaluation:**")
        col_p1, col_p2, col_p3 = st.columns(3)
        if col_p1.button("Hinglish Job Scam Preset"):
            analyzed_text = "Ghar baithe video like karke paise kamayein. Daily paghar 5000 INR milega. Easy task join now on Telegram: t.me/worktask2"
            st.rerun()
        if col_p2.button("Phishing Alert Preset"):
            analyzed_text = "Alert: Your netbanking will close today due to pending KYC verification. Please click this link immediately to link your PAN Card: https://sbi-verification.net/login"
            st.rerun()
        if col_p3.button("Safe Normal Message Preset"):
            analyzed_text = "Hello Professor, please check the attached project draft. I have reviewed the guidelines and completed all revisions. Thank you."
            st.rerun()

    # 2. Chat Conversation Log
    elif input_mode == "Chat Conversation Log":
        input_channel_label = "Chat Log"
        analyzed_text = st.text_area(
            "Paste consecutive chat log messages (e.g. Sender: message):",
            placeholder="User: Hello, I have an issue with the product\nSupport: Yes install AnyDesk so I can connect and help you\nSupport: Give me the ID code to verify",
            height=150
        )
        
        if st.button("Load Tech Support Chat Demo"):
            analyzed_text = (
                "Scammer: Hello, I am calling from Paytm Technical Support.\n"
                "Victim: Hi, my recent transaction failed but money was deducted.\n"
                "Scammer: Please download AnyDesk app from Play Store so we can trace your server link.\n"
                "Scammer: Once downloaded, tell me the 9-digit code."
            )
            st.rerun()

    # 3. WhatsApp Export File
    elif input_mode == "WhatsApp Export File (.txt)":
        input_channel_label = "WhatsApp Chat Export"
        uploaded_file = st.file_uploader("Upload exported WhatsApp chat history (.txt file):", type=["txt"])
        
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            raw_text = file_bytes.decode("utf-8")
            
            # Simple parser to remove metadata and join message bodies
            parsed_lines = []
            for line in raw_text.splitlines():
                # Format match: e.g. [31/05/26, 12:30:15] Name: Message OR 31/05/26, 12:30 - Name: Message
                match = re.search(r"-\s([^:]+):\s(.*)", line)
                if match:
                    parsed_lines.append(f"{match.group(1)}: {match.group(2)}")
                else:
                    # Fallback for other export headers
                    parts = line.split(":")
                    if len(parts) > 2:
                        parsed_lines.append(f"{parts[1].strip()}: {':'.join(parts[2:]).strip()}")
                        
            if parsed_lines:
                analyzed_text = "\n".join(parsed_lines)
                st.success(f"Parsed {len(parsed_lines)} chat lines successfully.")
                with st.expander("Show extracted chat content"):
                    st.text(analyzed_text)
            else:
                # Fallback to loading raw text if format didn't parse
                analyzed_text = raw_text
                st.info("Uploaded chat loaded directly as plain text.")
        else:
            st.info("Tip: Export a WhatsApp chat thread without media, and upload the resulting .txt file here.")

    # 4. Screenshot Upload (OCR)
    elif input_mode == "Screenshot Upload (OCR)":
        input_channel_label = "Screenshot OCR"
        uploaded_image = st.file_uploader("Upload screenshot image (WhatsApp, SMS, Telegram, Instagram chats, etc.):", type=["png", "jpg", "jpeg"])
        
        if uploaded_image is not None:
            col_img, col_text = st.columns([1, 1])
            with col_img:
                st.image(uploaded_image, caption="Uploaded Screenshot", use_container_width=True)
            
            with col_text:
                with st.spinner("Extracting text from screenshot using OCR..."):
                    extracted_text, ocr_engine = extract_text_from_image(uploaded_image)
                st.info(f"OCR Engine utilized: **{ocr_engine}**")
                
                # Check for warnings in fallback text
                if "[Warning" in extracted_text:
                    st.warning(extracted_text)
                    analyzed_text = ""
                else:
                    analyzed_text = st.text_area("Extracted OCR Text (editable):", value=extracted_text, height=200)
        else:
            st.info("Upload an image screenshot containing suspicious texts or chat bubbles.")
            
            # Preset OCR text check for simulation
            st.markdown("**Simulate Screenshot Text matches:**")
            col_o1, col_o2 = st.columns(2)
            if col_o1.button("Simulate Instagram Crypto Chat Screenshot"):
                analyzed_text = "Investment Manager: Hi dear! Connect your wallet and type your recovery phrase. You will claim free 2 BTC bonus instantly. It is safe."
                st.success("Crypto Scam screenshot simulation loaded.")
                st.rerun()
            if col_o2.button("Simulate UPI Scratch Card Screenshot"):
                analyzed_text = "Congratulations! You won Rs 850 cashback. Enter UPI PIN to claim this cashback direct to your bank account."
                st.success("UPI Scam screenshot simulation loaded.")
                st.rerun()

    # 5. URL Link Analyzer
    elif input_mode == "URL Link Analyzer":
        input_channel_label = "URL Scan"
        analyzed_text = st.text_input(
            "Enter suspicious domain link / URL to analyze:",
            placeholder="Example: http://sbi-netbanking-secure.in/signin.php"
        )
        
        st.markdown("**Sample suspicious domains to check:**")
        col_u1, col_u2, col_u3 = st.columns(3)
        if col_u1.button("http://bit.ly/kbc-win"):
            analyzed_text = "http://bit.ly/kbc-win"
            st.rerun()
        if col_u2.button("https://amz-login-renew.com"):
            analyzed_text = "https://amz-login-renew.com"
            st.rerun()
        if col_u3.button("http://192.168.1.105/bank.php"):
            analyzed_text = "http://192.168.1.105/bank.php"
            st.rerun()

    # 6. Spoken Voice Audio
    elif input_mode == "Spoken Voice Audio":
        input_channel_label = "Voice Transcript"
        st.write("Upload a voice recording or choose a pre-recorded call recording demo:")
        
        uploaded_audio = st.file_uploader("Upload audio file (.wav, .mp3):", type=["wav", "mp3"])
        
        demo_voice = st.selectbox(
            "Or choose a Preloaded Demo Call Recording:",
            ["Select a demo file...", "demo_job_scam.wav", "demo_upi_scam.wav", "demo_otp_scam.wav", "demo_safe_chat.wav"]
        )
        
        selected_audio_file = None
        selected_filename = None
        
        if uploaded_audio is not None:
            selected_audio_file = uploaded_audio
            selected_filename = uploaded_audio.name
            st.audio(uploaded_audio)
        elif demo_voice != "Select a demo file...":
            selected_audio_file = demo_voice
            selected_filename = demo_voice
            # Create a mock visual indicator for the demo audio
            st.info(f"Selected demo recording: {demo_voice}")
            st.audio(np.zeros(22050), format="audio/wav", sample_rate=22050)
            
        if selected_audio_file:
            with st.spinner("Transcribing spoken audio contents to text..."):
                trans_text, voice_method = transcribe_audio(selected_audio_file, selected_filename)
            st.info(f"Transcription method: **{voice_method}**")
            
            if "[Warning" in trans_text:
                st.warning(trans_text)
                analyzed_text = ""
            else:
                analyzed_text = st.text_area("Transcribed call speech (editable):", value=trans_text, height=120)

    import re # Make sure regex is available for url checking inside app

    # Triggering Scan
    if analyzed_text:
        st.markdown("---")
        if st.button("🛡️ INITIATE SCAM SHIELD SCAN", use_container_width=True):
            with st.spinner("Running hybrid rule-based, ML-classifier, and LLM reasoning check..."):
                # Run analyzer
                api_key_to_use = config.GEMINI_API_KEY
                
                # Check if user only analyzed a URL
                url_mode_only = input_mode == "URL Link Analyzer"
                text_to_analyze = analyzed_text
                
                # If it's a URL only input, wrap it to helper text to provide context for classifier
                if url_mode_only:
                    text_to_analyze = f"Check this suspicious URL: {analyzed_text}"
                
                result = analyze_suspicious_input(text_to_analyze, api_key_to_use)
                
                # Save scan results to local SQLite database
                log_scan(
                    input_type=input_channel_label,
                    input_text=analyzed_text,
                    scam_score=result["scam_score"],
                    risk_level=result["risk_level"],
                    category=result["category"],
                    confidence=result["confidence"],
                    user_metadata="Web GUI Scanner"
                )
                
                # Display Results
                st.markdown("### 📊 Scam Shield Diagnostics Report")
                
                # Split report into two columns
                col_score, col_details = st.columns([1, 2])
                
                with col_score:
                    # Determine styling based on risk level
                    risk_class = "risk-safe"
                    badge_class = "badge-safe"
                    color_accent = "#10b981"
                    
                    if result["risk_level"] == "Suspicious":
                        risk_class = "risk-suspicious"
                        badge_class = "badge-secondary"
                        color_accent = "#f59e0b"
                    elif result["risk_level"] == "High Risk":
                        risk_class = "risk-high"
                        badge_class = "badge-high"
                        color_accent = "#ef4444"
                    elif result["risk_level"] == "Critical":
                        risk_class = "risk-critical"
                        badge_class = "badge-critical"
                        color_accent = "#ef4444"
                        
                    # Create Plotly Gauge for Score
                    fig = go.Figure(go.Indicator(
                        mode = "gauge+number",
                        value = result["scam_score"],
                        domain = {'x': [0, 1], 'y': [0, 1]},
                        title = {'text': "SCAM DANGER SCORE", 'font': {'size': 18, 'family': 'Orbitron', 'color': '#ffffff'}},
                        gauge = {
                            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#ffffff"},
                            'bar': {'color': color_accent},
                            'bgcolor': "rgba(22, 31, 56, 0.4)",
                            'borderwidth': 2,
                            'bordercolor': "rgba(255,255,255,0.1)",
                            'steps': [
                                {'range': [0, 30], 'color': 'rgba(16, 185, 129, 0.15)'},
                                {'range': [30, 55], 'color': 'rgba(245, 158, 11, 0.15)'},
                                {'range': [55, 80], 'color': 'rgba(239, 68, 68, 0.15)'},
                                {'range': [80, 100], 'color': 'rgba(185, 28, 28, 0.25)'}
                            ],
                            'threshold': {
                                'line': {'color': "#ffffff", 'width': 4},
                                'thickness': 0.75,
                                'value': result["scam_score"]}
                        }
                    ))
                    
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font={'color': "#ffffff", 'family': "Outfit"},
                        height=250,
                        margin=dict(l=20, r=20, t=50, b=20)
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Risk summary panel
                    st.markdown(f"""
                        <div class='cyber-card {risk_class}' style='text-align: center;'>
                            <h4 style='margin: 0px;'>RISK LEVEL</h4>
                            <span class='cyber-badge {badge_class}' style='font-size: 1.3em; margin: 10px 0;'>{result["risk_level"]}</span>
                            <p style='color: #8a9fc4; margin-bottom: 0px; font-size: 0.9em;'>
                                Category: <b>{result["category"]}</b><br>
                                AI Confidence: <b>{result["confidence"]}%</b>
                            </p>
                        </div>
                    """, unsafe_allow_html=True)
                    
                with col_details:
                    # Detect Language
                    detected_lang = detect_language(analyzed_text if not url_mode_only else analyzed_text)
                    
                    # Language tag
                    st.markdown(f"🌐 **Linguistic Analysis**: Identified language structure: `{detected_lang}`")
                    
                    # AI Explanation
                    st.markdown(f"""
                        <div class='cyber-card' style='border-left: 5px solid #00f0ff;'>
                            <h4 style='color: #00f0ff; margin-top: 0px;'>🧠 AI Explainability Engine</h4>
                            <p style='line-height: 1.6; font-size: 1.05em;'>{result["explanation"]}</p>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    # Red Flags and Tactics
                    st.markdown("#### 🚩 Highlighted Scam Indicators & Manipulation Tactics:")
                    for flag in result["red_flags"]:
                        st.markdown(f"🚨 <span style='color: #fca5a5;'>{flag}</span>", unsafe_allow_html=True)
                        
                    # Recommendations
                    st.markdown("---")
                    st.markdown("#### 🛡️ Required Safety Recommendations:")
                    for rec in result["recommendations"]:
                        st.markdown(f"✅ **{rec}**")
                        
            if result["scam_score"] < 30:
                st.balloons()
            else:
                st.info("Diagnostic completed. Action recommended.")

# TAB 2: ADMIN ANALYTICS DASHBOARD
with tab2:
    st.markdown("""
        <div class='cyber-card'>
            <h3>📊 Platform Command Center - Incident Analytics</h3>
            <p>Admin summary showing aggregate scans distributions, threat levels frequency, scan types formats, and incident daily trends over time.</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Load stats
    stats = get_analytics_summary()
    
    if stats["total_scans"] == 0:
        st.info("No scans recorded yet. Run a Scam Scan to populate details.")
    else:
        # Stat cards in row
        st.markdown(f"""
            <div style="display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px;">
                <div class="cyber-card" style="flex: 1; min-width: 200px; text-align: center; margin-bottom: 0px !important;">
                    <h5 style="color: #8a9fc4; margin: 0px;">TOTAL SCANS</h5>
                    <h2 style="font-size: 2.5em; color: #00f0ff; margin: 10px 0px;">{stats["total_scans"]}</h2>
                </div>
                <div class="cyber-card" style="flex: 1; min-width: 200px; text-align: center; margin-bottom: 0px !important;">
                    <h5 style="color: #8a9fc4; margin: 0px;">AVERAGE DANGER INDEX</h5>
                    <h2 style="font-size: 2.5em; color: #f59e0b; margin: 10px 0px;">{stats["avg_score"]}/100</h2>
                </div>
                <div class="cyber-card" style="flex: 1; min-width: 200px; text-align: center; margin-bottom: 0px !important;">
                    <h5 style="color: #8a9fc4; margin: 0px;">CRITICAL / HIGH THREATS</h5>
                    <h2 style="font-size: 2.5em; color: #ef4444; margin: 10px 0px;">{stats["high_risk_count"]}</h2>
                </div>
            </div>
        """, unsafe_allow_html=True)
        
        # Grid layout for charts
        col_c1, col_c2 = st.columns([1, 1])
        
        with col_c1:
            # 1. Category distribution chart
            cats = list(stats["category_distribution"].keys())
            counts = list(stats["category_distribution"].values())
            
            fig_cat = px.bar(
                x=counts,
                y=cats,
                orientation='h',
                title="Common Incident Scam Types",
                labels={'x': 'Number of Detections', 'y': 'Scam Category'},
                color=counts,
                color_continuous_scale=px.colors.sequential.Purples
            )
            fig_cat.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': "#ffffff", 'family': "Outfit"},
                coloraxis_showscale=False
            )
            fig_cat.update_xaxes(gridcolor='rgba(255,255,255,0.05)')
            fig_cat.update_yaxes(gridcolor='rgba(255,255,255,0.05)')
            st.plotly_chart(fig_cat, use_container_width=True)
            
        with col_c2:
            # 2. Daily trends chart
            trend_df = pd.DataFrame(stats["daily_trends"])
            if not trend_df.empty:
                fig_trend = px.line(
                    trend_df,
                    x="date",
                    y="scans",
                    title="Volume Trends - Incident History",
                    labels={'date': 'Date', 'scans': 'Total Scans Checkups'},
                    markers=True
                )
                # Style line
                fig_trend.update_traces(line_color="#00f0ff", line_width=3)
                fig_trend.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#ffffff", 'family': "Outfit"}
                )
                fig_trend.update_xaxes(gridcolor='rgba(255,255,255,0.05)')
                fig_trend.update_yaxes(gridcolor='rgba(255,255,255,0.05)')
                st.plotly_chart(fig_trend, use_container_width=True)
                
        col_c3, col_c4 = st.columns([1, 1])
        
        with col_c3:
            # 3. Input Channels Pie
            channels = list(stats["input_type_distribution"].keys())
            channel_counts = list(stats["input_type_distribution"].values())
            
            fig_pie = px.pie(
                names=channels,
                values=channel_counts,
                title="Input Vector Channels Analyzed",
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': "#ffffff", 'family': "Outfit"}
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col_c4:
            # 4. Danger score trend lines
            if not trend_df.empty:
                fig_score_trend = px.line(
                    trend_df,
                    x="date",
                    y="avg_score",
                    title="Daily Average Danger Threat Level",
                    labels={'date': 'Date', 'avg_score': 'Avg Threat Rating'},
                    markers=True
                )
                fig_score_trend.update_traces(line_color="#a855f7", line_width=3)
                fig_score_trend.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#ffffff", 'family': "Outfit"}
                )
                fig_score_trend.update_xaxes(gridcolor='rgba(255,255,255,0.05)')
                fig_score_trend.update_yaxes(gridcolor='rgba(255,255,255,0.05)')
                st.plotly_chart(fig_score_trend, use_container_width=True)

        # Audit Logs Table
        st.markdown("### 📋 Security Audit Logs")
        recent_logs = get_recent_logs(50)
        if recent_logs:
            logs_df = pd.DataFrame(recent_logs)
            # Reorder / rename cols for visual appeal
            logs_df = logs_df.rename(columns={
                "id": "Log ID",
                "timestamp": "Timestamp",
                "input_type": "Channel Vector",
                "input_text": "Content Snippet",
                "scam_score": "Danger Rating",
                "risk_level": "Severity",
                "category": "Classified Category",
                "confidence": "Conf %"
            })
            st.dataframe(logs_df, use_container_width=True, hide_index=True)
            
            # Export logs option
            csv_data = logs_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "Export Audit Logs to CSV",
                data=csv_data,
                file_name="scam_shield_audit_logs.csv",
                mime="text/csv"
            )
        else:
            st.text("No audit log records available.")

# TAB 3: ABOUT & FAQ
with tab3:
    st.markdown("""
        <div class='cyber-card'>
            <h3>🛡️ About AI Scam Shield</h3>
            <p><b>AI Scam Shield</b> is a production-grade multi-agent safety framework designed to protect vulnerable digital citizens—senior citizens, students, job seekers, and online shoppers—from being duped by online cyber scams.</p>
            <p>Our platform uses a <b>hybrid security detection methodology</b>: rule-based scans capture signature indicators immediately, local Scikit-Learn classifiers handle standard text pattern identification, and advanced LLM (Google Gemini) performs zero-shot linguistic reasoning to explain 'why' and 'how' a threat operates.</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
        ### ❓ Frequently Asked Questions (FAQ)
        
        **Q: What target channels are supported?**
        - **Direct Text**: Copy and paste any suspicious text message.
        - **Chat Logs**: Paste transcripts from WhatsApp, Telegram, Instagram.
        - **WhatsApp exports**: Upload exported `.txt` chat logs directly.
        - **Screenshot OCR**: Image files are scanned using local models (EasyOCR/Tesseract) or Gemini Vision API to convert characters into text.
        - **URL Intelligent scans**: Parses links to find brand typosquatting, TLD risks, redirection shorteners, or phishing keywords.
        - **Spoken call audio**: Transcribes phone voice messages to evaluate verbal pressure.
        
        **Q: Does my message leave my system?**
        - If you do not configure a Google Gemini API Key, all evaluations are run **100% locally** on your CPU using python libraries and local Scikit-Learn checkpoints.
        - If you input a Gemini API Key, message chunks are processed by Google's secure APIs for natural language assessment.
        
        **Q: How does the system handle multi-lingual Indian contexts?**
        - The engine handles **mixed language code-switching** (e.g. Hinglish: English letters spelling Hindi words like 'paisa double' and Gujlish: English letters spelling Gujarati words like 'rokan karo'). Regular expression databases and the language classifiers have been trained explicitly on transliterated strings.
        
        **Q: Who do I report suspicious messages to?**
        - In India, you can register official cyber complaints at [cybercrime.gov.in](https://www.cybercrime.gov.in) or call the national cyber hotline at **1930**.
    """)
