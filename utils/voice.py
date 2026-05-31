import logging
import mimetypes
from typing import Tuple
import config

logger = logging.getLogger("AIScamShield.VoiceTranscriber")

# Standard presets for demo/simulation
VOICE_DEMO_PRESETS = {
    "demo_job_scam.wav": "Dear friend, you have been selected for part time work from home. Daily earn 5000 rupees. No fees required. Join our telegram channel now to receive your payment details.",
    "demo_upi_scam.wav": "Hello, aapko humari taraf se cashback offer mila hai. GPay open karke QR code scan kijiye aur UPI PIN type kijiye.",
    "demo_safe_chat.wav": "Hello beta, are you reaching home today by 7 PM? Call me when you leave the office.",
    "demo_otp_scam.wav": "Sir, I am calling from card services. Your debit card is blocked. I have sent an OTP to your phone. Tell me that code immediately so I can unblock it."
}

def transcribe_audio(audio_file_or_path, filename: str = None) -> Tuple[str, str]:
    """
    Transcribes audio to text.
    If Gemini API key is configured, uses Gemini to perform speech-to-text.
    Otherwise, matches against demo filenames or returns a friendly error.
    """
    name = filename or getattr(audio_file_or_path, "name", "")
    
    # 1. Check if it's one of our pre-configured demo files
    if name in VOICE_DEMO_PRESETS:
        logger.info(f"Demo audio file match found: {name}")
        return VOICE_DEMO_PRESETS[name], "Voice Demo Simulator"
        
    # 2. Try Gemini audio transcription (multimodal support)
    if config.GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            logger.info("Sending audio to Gemini for speech-to-text...")
            genai.configure(api_key=config.GEMINI_API_KEY)
            model = genai.GenerativeModel("gemini-1.5-flash")
            
            # Read file bytes
            if hasattr(audio_file_or_path, "read"):
                audio_bytes = audio_file_or_path.read()
                # Reset pointer
                audio_file_or_path.seek(0)
            else:
                with open(audio_file_or_path, "rb") as f:
                    audio_bytes = f.read()

            # Determine mime type
            mime_type = "audio/wav"
            if name:
                guess = mimetypes.guess_type(name)[0]
                if guess:
                    mime_type = guess

            prompt = (
                "You are an expert audio transcriptionist. Transcribe the spoken text in this audio clip. "
                "The audio might be in English, Hindi, Hinglish, Gujarati, or Gujlish. "
                "Output ONLY the exact transcribed text. Do not add any annotations, formatting, or greetings."
            )
            
            response = model.generate_content([
                prompt,
                {
                    "mime_type": mime_type,
                    "data": audio_bytes
                }
            ])
            
            transcript = response.text.strip()
            if transcript:
                return transcript, "Google Gemini Speech-to-Text"
                
        except Exception as e:
            logger.error(f"Gemini Speech-to-Text failed: {e}")
            
    # 3. Fallback message for custom files if Gemini is unavailable
    fallback_text = (
        "[Warning: System could not run Speech-to-Text since GEMINI_API_KEY is not configured. "
        f"To transcribe your own custom audio file '{name}', please configure your API key in the sidebar. "
        "Alternatively, you can select one of our preloaded Demo Audio options to see how voice analysis works.]"
    )
    return fallback_text, "Speech-to-Text Fallback"
