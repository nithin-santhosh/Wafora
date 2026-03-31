import os
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

# --- Global model variable, loaded once by the WAF core ---
ml_model = None

# Delay loading the model until the WAF proxy attempts to use it.
# This prevents the Flask server from failing on startup if the model path is wrong,
# allowing the Flask routes to be accessible first.
def load_ml_model():
    global ml_model
    if ml_model is None:
        try:
            # We already confirmed existence in app.py, so this should succeed.
            ml_model = joblib.load(MODEL_PATH)
        except Exception as e:
            # Re-raise error clearly if loading fails (e.g., corrupted file)
            raise RuntimeError(f"FATAL: ML Model loading failed: {e}")
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
