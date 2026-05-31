import sqlite3
import datetime
import random
import logging
from typing import Dict, Any, List
import config

logger = logging.getLogger("AIScamShield.DBHelper")

def get_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if it doesn't exist."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    input_text TEXT NOT NULL,
                    scam_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    category TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    user_metadata TEXT
                )
            """)
            conn.commit()
            
            # Check if database is empty. If empty, populate mock data for demo.
            cursor.execute("SELECT COUNT(*) FROM scan_logs")
            count = cursor.fetchone()[0]
            if count == 0:
                logger.info("Database is empty. Populating mock scan logs for analytics demonstration...")
                populate_mock_data(conn)
    except Exception as e:
        logger.error(f"Failed to initialize SQLite database: {e}")

def log_scan(input_type: str, input_text: str, scam_score: int, risk_level: str, category: str, confidence: int, user_metadata: str = None) -> None:
    """Logs a scan result to the database."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Truncate text if it is extremely long for database performance
        truncated_text = input_text[:1000] if input_text else ""
        
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs 
                (timestamp, input_type, input_text, scam_score, risk_level, category, confidence, user_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, input_type, truncated_text, scam_score, risk_level, category, confidence, user_metadata))
            conn.commit()
            logger.info("Scan log saved to SQLite.")
    except Exception as e:
        logger.error(f"Failed to log scan to SQLite: {e}")

def get_analytics_summary() -> Dict[str, Any]:
    """Compiles statistics for the admin dashboard."""
    init_db()  # Ensure tables exist
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Basic Stats
            cursor.execute("SELECT COUNT(*), AVG(scam_score), SUM(CASE WHEN risk_level IN ('High Risk', 'Critical') THEN 1 ELSE 0 END) FROM scan_logs")
            total_scans, avg_score, high_risk_count = cursor.fetchone()
            
            total_scans = total_scans or 0
            avg_score = round(avg_score, 1) if avg_score else 0.0
            high_risk_count = high_risk_count or 0
            
            # 2. Category Distribution
            cursor.execute("SELECT category, COUNT(*) as count FROM scan_logs GROUP BY category ORDER BY count DESC")
            cat_rows = cursor.fetchall()
            category_distribution = {row["category"]: row["count"] for row in cat_rows}
            
            # 3. Input Type Distribution
            cursor.execute("SELECT input_type, COUNT(*) as count FROM scan_logs GROUP BY input_type ORDER BY count DESC")
            type_rows = cursor.fetchall()
            input_type_distribution = {row["input_type"]: row["count"] for row in type_rows}
            
            # 4. Daily Trends (Past 7 days)
            cursor.execute("""
                SELECT substr(timestamp, 1, 10) as date, COUNT(*) as count, AVG(scam_score) as avg_daily_score
                FROM scan_logs 
                GROUP BY date 
                ORDER BY date ASC
                LIMIT 30
            """)
            trend_rows = cursor.fetchall()
            daily_trends = [
                {"date": row["date"], "scans": row["count"], "avg_score": round(row["avg_daily_score"], 1)}
                for row in trend_rows
            ]
            
            # 5. Risk Level distribution
            cursor.execute("SELECT risk_level, COUNT(*) as count FROM scan_logs GROUP BY risk_level")
            risk_rows = cursor.fetchall()
            risk_distribution = {row["risk_level"]: row["count"] for row in risk_rows}

            return {
                "total_scans": total_scans,
                "avg_score": avg_score,
                "high_risk_count": high_risk_count,
                "category_distribution": category_distribution,
                "input_type_distribution": input_type_distribution,
                "daily_trends": daily_trends,
                "risk_distribution": risk_distribution
            }
    except Exception as e:
        logger.error(f"Failed to fetch analytics summary: {e}")
        return {
            "total_scans": 0,
            "avg_score": 0.0,
            "high_risk_count": 0,
            "category_distribution": {},
            "input_type_distribution": {},
            "daily_trends": [],
            "risk_distribution": {}
        }

def get_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns a list of recent scan records."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, input_type, input_text, scam_score, risk_level, category, confidence
                FROM scan_logs
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Failed to fetch logs: {e}")
        return []

def clear_logs() -> None:
    """Wipes all rows from the scan logs."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_logs")
            conn.commit()
            logger.info("Database logs cleared.")
    except Exception as e:
        logger.error(f"Failed to clear logs: {e}")

def populate_mock_data(conn):
    """Generates realistic scan records for the past 7 days."""
    categories = [
        ("Job Scam", 75, "High Risk", "Work from home task click youtube video links"),
        ("UPI Scam", 85, "Critical", "Scan this QR code and type your UPI PIN to claim cashback"),
        ("OTP / Account Takeover Scam", 90, "Critical", "Please share the OTP you just received from your bank"),
        ("Phishing", 80, "Critical", "Your netbanking account is suspended. Verify KYC here: hdfc-login.xyz"),
        ("Lottery Scam", 70, "High Risk", "KBC Lucky draw won 25 Lakhs. Pay tax processing fees"),
        ("Investment Scam", 65, "High Risk", "Double your capital in one day. Guaranteed returns on Telegram"),
        ("Customer Support Scam", 85, "Critical", "Tech Support executive calling, please install AnyDesk remote access"),
        ("Shopping Scam", 50, "Suspicious", "iPhone 15 Pro Max for just 2999. Today clearout sale"),
        ("Romance Scam", 60, "High Risk", "I am in Delhi customs airport airport, send money for medical check"),
        ("Crypto Scam", 75, "High Risk", "USDT secure deposit, input your MetaMask private seed phrase"),
        ("Safe", 10, "Safe", "Hello dad, please transfer the grocery money. Thanks"),
        ("Safe", 5, "Safe", "Hi, the team alignment call is rescheduled to 3 PM tomorrow. See you"),
        ("Safe", 12, "Safe", "Your one-time login passcode is 392019. Do not share.")
    ]
    
    input_types = ["Direct Text", "WhatsApp Chat", "Screenshot OCR", "URL Link", "Voice Transcript", "Email Content"]
    cursor = conn.cursor()
    
    now = datetime.datetime.now()
    
    # Generate 60 records spread across the last 7 days
    for i in range(60):
        # Determine randomized date
        days_ago = random.randint(0, 6)
        minutes_ago = random.randint(1, 1440)
        log_time = now - datetime.timedelta(days=days_ago, minutes=minutes_ago)
        timestamp_str = log_time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Pick random inputs and outputs
        cat_info = random.choice(categories)
        cat_name, base_score, risk_lvl, text_body = cat_info
        
        # Add random variations
        jitter = random.randint(-10, 10)
        score = max(0, min(100, base_score + jitter))
        
        # Recalculate risk level to match score
        if score < 30:
            risk_lvl = "Safe"
        elif score < 55:
            risk_lvl = "Suspicious"
        elif score < 80:
            risk_lvl = "High Risk"
        else:
            risk_lvl = "Critical"
            
        conf = random.randint(70, 99)
        inp_type = random.choice(input_types)
        
        cursor.execute("""
            INSERT INTO scan_logs 
            (timestamp, input_type, input_text, scam_score, risk_level, category, confidence, user_metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp_str, inp_type, text_body, score, risk_lvl, cat_name, conf, "Mock Scan Data"))
        
    conn.commit()
    logger.info("Mock database logs populated successfully.")
