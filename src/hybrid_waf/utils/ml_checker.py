import os
import hashlib
import joblib

# --- CONFIGURATION ---
ML_THRESHOLD = 0.50 

# 1. Get the directory of the current script (ml_checker.py)
script_dir = os.path.dirname(os.path.abspath(__file__))

# 2. Construct the absolute path to the model file
MODEL_PATH = os.path.join(
    script_dir,
    "..",
    "models",
    "ml_model.pkl"
)

# --- Global model variable and integrity hash, loaded once by the WAF core ---
ml_model = None
_model_hash = None


def _compute_file_hash(path: str) -> str:
    """Computes the SHA-256 hash of a file to verify its integrity."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# Delay loading the model until the WAF proxy attempts to use it.
# This prevents the Flask server from failing on startup if the model path is wrong,
# allowing the Flask routes to be accessible first.
def load_ml_model():
    global ml_model, _model_hash
    if ml_model is None:
        try:
            # Record the hash of the model file before loading it.
            # This baseline hash is used to detect runtime file replacement.
            _model_hash = _compute_file_hash(MODEL_PATH)
            # We already confirmed existence in app.py, so this should succeed.
            ml_model = joblib.load(MODEL_PATH)
        except Exception as e:
            # Re-raise error clearly if loading fails (e.g., corrupted file)
            raise RuntimeError(f"FATAL: ML Model loading failed: {e}")
    else:
        # On subsequent calls verify the model file has not been modified since
        # the initial load, guarding against runtime file-replacement attacks.
        current_hash = _compute_file_hash(MODEL_PATH)
        if current_hash != _model_hash:
            raise RuntimeError(
                "FATAL: ML Model file integrity check failed. "
                "The model file has been modified since server startup. "
                "Refusing to use the modified model."
            )
    return ml_model


def check_ml_prediction(features: list) -> float:
    """
    Takes a list of eight features and returns the ML prediction probability (score).
    Returns a float between 0.0 and 1.0, representing confidence of being malicious.
    """
    model = load_ml_model() # Ensure model is loaded
    
    # The model predicts probabilities for both classes [Safe, Malicious].
    # [1] is the index for the 'malicious' class probability (the score we need).
    prediction_score = model.predict_proba([features])[0][1]
    return prediction_score
