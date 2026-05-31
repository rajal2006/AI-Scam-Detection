import os
import joblib
import logging
from typing import Dict, Any, Tuple
import config

logger = logging.getLogger("AIScamShield.MLModel")

# Cache model in memory
_MODEL_PIPELINE = None

def load_ml_model() -> Any:
    """
    Loads the trained TF-IDF + Classifier model from disk.
    If the model doesn't exist, it triggers dynamic self-training.
    """
    global _MODEL_PIPELINE
    if _MODEL_PIPELINE is not None:
        return _MODEL_PIPELINE
        
    model_path = config.MODEL_PATH
    
    # Validate that model has the updated categories (e.g. OTP / Account Takeover Scam) before loading
    if os.path.exists(model_path):
        try:
            temp_model = joblib.load(model_path)
            if not hasattr(temp_model, "classes_") or "OTP / Account Takeover Scam" not in temp_model.classes_:
                os.remove(model_path)
                logger.info("Detected old model version. Deleted it to trigger retraining.")
        except Exception as e:
            logger.warning(f"Failed to validate existing model, deleting for fresh build: {e}")
            try:
                os.remove(model_path)
            except:
                pass
            
    if not os.path.exists(model_path):
        logger.warning(f"ML model file not found at {model_path}. Initiating automatic dynamic self-training...")
        try:
            from models.train import train_and_save_model
            train_and_save_model()
            logger.info("Dynamic self-training completed successfully.")
        except Exception as e:
            logger.error(f"Failed to auto-train ML model: {e}")
            return None
            
    try:
        if os.path.exists(model_path):
            _MODEL_PIPELINE = joblib.load(model_path)
            logger.info("ML model pipeline loaded successfully from disk.")
            return _MODEL_PIPELINE
    except Exception as e:
        logger.error(f"Error reading model file {model_path}: {e}. Model will run in disabled state.")
        
    return None

def predict_scam_ml(text: str) -> Dict[str, Any]:
    """
    Classifies a text sample using the local ML model.
    Returns prediction score, category and class probabilities.
    """
    if not text or not isinstance(text, str) or len(text.strip()) < 3:
        return {
            "ml_scam_score": 0,
            "ml_category": "Safe",
            "confidence": 100,
            "probabilities": {"Safe": 1.0}
        }
        
    model = load_ml_model()
    if model is None:
        logger.warning("ML Model not loaded. Returning empty ML results.")
        return {
            "ml_scam_score": 0,
            "ml_category": "Unknown Scam",
            "confidence": 0,
            "probabilities": {}
        }
        
    try:
        # Preprocessing is handled by the pipeline (lowercase, TfidfVectorizer default tokenizer)
        probabilities = model.predict_proba([text])[0]
        classes = model.classes_
        
        # Build predictions dict
        probs_dict = {str(cls): float(prob) for cls, prob in zip(classes, probabilities)}
        
        # Get highest probability
        pred_category = model.predict([text])[0]
        pred_prob = probs_dict.get(pred_category, 0.0)
        
        # Scaling scam score:
        # If predicted Safe: score ranges 0-29
        # If predicted Scam: score ranges 30-100 based on prediction confidence
        if pred_category == "Safe":
            ml_scam_score = int((1.0 - pred_prob) * 29)
        else:
            # Shift scam classes to higher score brackets
            ml_scam_score = int(30 + (pred_prob * 70))
            
        confidence = int(pred_prob * 100)
        
        return {
            "ml_scam_score": ml_scam_score,
            "ml_category": pred_category,
            "confidence": confidence,
            "probabilities": probs_dict
        }
    except Exception as e:
        logger.error(f"Failed to execute model prediction: {e}")
        return {
            "ml_scam_score": 0,
            "ml_category": "Unknown Scam",
            "confidence": 0,
            "probabilities": {}
        }
