import os
import secrets
import logging
import sys
from flask import Flask, request
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

# --- 1. CONFIGURATION PATHS ---
# Define the project root directory relative to this script (app.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define the model path and log path relative to BASE_DIR
MODEL_PATH = os.path.join(BASE_DIR, 'src', 'hybrid_waf', 'models', 'ml_model.pkl')
LOG_FILE_PATH = os.path.join(BASE_DIR, 'logs', 'detections.log')
log_dir = os.path.dirname(LOG_FILE_PATH)

# --- 2. LOGGING SETUP ---
if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)

# Set up a specific logger for WAF detections
waf_logger = logging.getLogger('waf')
waf_logger.setLevel(logging.INFO)
if not waf_logger.handlers:
    handler = logging.FileHandler(LOG_FILE_PATH, mode='a')
    # FIX: Removed the specific 'datefmt' to use Python's default logging timestamp 
    # (which includes milliseconds and a comma, e.g., 'HH:MM:SS,mmm').
    # This aligns the log format with the regex parser in static/home.js.
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    waf_logger.addHandler(handler)
# --- END LOGGING SETUP ---

# --- 3. CRITICAL: Model File Check ---
# Check model file path *before* Flask instantiation
if not os.path.exists(MODEL_PATH):
    print("\n" + "="*70, file=sys.stderr)
    print("FATAL ERROR: ML model file not found!", file=sys.stderr)
    print(f"Expected path: {MODEL_PATH}", file=sys.stderr)
    print("The Flask app cannot run without the model.", file=sys.stderr)
    print("="*70, file=sys.stderr)
    sys.exit(1) # Exit gracefully if critical file is missing
# --- END MODEL CHECK ---


app = Flask(__name__)

# --- 4. SECRET KEY ---
# Use the env var in production; fall back to a random key per process for development.
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)


# --- 5. SECURITY HEADERS ---
@app.after_request
def add_security_headers(response):
    """Attaches security-related HTTP headers to every response."""
    # Prevent browsers from MIME-sniffing the content type
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Disallow framing to protect against click-jacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Control the referrer information sent with requests
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Content Security Policy:
    #   - default-src 'self'          : only load resources from the same origin
    #   - script-src cdn.jsdelivr.net : allow Chart.js from jsDelivr CDN
    #   - style-src 'unsafe-inline'   : needed for inline <style> blocks and
    #                                   dynamically injected styles in home.js
    #   - font-src fonts.gstatic.com  : allow Google Fonts
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


if __name__ == '__main__':
    # Default to localhost; set FLASK_HOST=0.0.0.0 only when running behind a
    # reverse proxy or inside a container that handles external exposure.
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', '5000'))
    # Run with debug=False for stable logging
    app.run(host=host, port=port, debug=False)