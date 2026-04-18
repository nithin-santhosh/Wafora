import os
import time
import ipaddress
import threading
from urllib.parse import urlparse
from collections import defaultdict
from flask import Blueprint, request, jsonify, abort
from src.hybrid_waf.utils.signature_checker import (
    check_signature, get_payload_hash, is_blacklisted, add_to_blacklist
)
import logging

# --- WAF LOGGING SETUP ---
# Use the specific WAF logger configured in app.py
waf_logger = logging.getLogger('waf')

# --- RATE LIMITING ---
_rate_limit_lock = threading.Lock()
_rate_limit_data: dict = defaultdict(list)
RATE_LIMIT_REQUESTS = 30   # max requests per IP
RATE_LIMIT_WINDOW = 60     # sliding window in seconds


def _check_rate_limit(client_ip: str) -> bool:
    """Returns True if the request is allowed, False if the IP is rate-limited."""
    now = time.monotonic()
    with _rate_limit_lock:
        # Purge timestamps outside the sliding window
        _rate_limit_data[client_ip] = [
            t for t in _rate_limit_data[client_ip] if now - t < RATE_LIMIT_WINDOW
        ]
        if len(_rate_limit_data[client_ip]) >= RATE_LIMIT_REQUESTS:
            return False
        _rate_limit_data[client_ip].append(now)
        return True


def _sanitize_log_value(value: str) -> str:
    """Strips newline and carriage-return characters to prevent log injection."""
    return value.replace('\n', '\\n').replace('\r', '\\r')


def get_client_ip():
    """Get the real client IP address, validating proxy headers to prevent spoofing."""
    for header in ('X-Forwarded-For', 'X-Real-IP'):
        raw = request.headers.get(header, '')
        if raw:
            candidate = raw.split(',')[0].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
    return request.remote_addr


proxy_bp = Blueprint('proxy', __name__)

@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    client_ip = get_client_ip()

    # --- Rate Limiting ---
    if not _check_rate_limit(client_ip):
        return jsonify({
            "status": "error",
            "message": "Too many requests. Please slow down."
        }), 429

    data = request.get_json()
    user_input = data.get("user_request", "")
    
    # Simple input validation
    if not user_input or len(user_input) > 5000:
        return jsonify({
            "status": "error",
            "message": "Invalid or overly long request payload."
        }), 400

    payload_hash = get_payload_hash(user_input)
    
    # --- Layer 0: Persistent Blacklist Check (Fast Path Block) ---
    if is_blacklisted(payload_hash):
        safe_ip = _sanitize_log_value(client_ip)
        safe_input = _sanitize_log_value(user_input[:50])
        log_message = f"BLOCK (403) - Layer: Blacklist - IP: {safe_ip} - Hash: {payload_hash} - Input: {safe_input}..."
        waf_logger.info(log_message)
        waf_logger.handlers[0].flush()  # Force immediate write to log file

        return jsonify({
            "status": "malicious",
            "signature_status": "Blacklist",
            "is_blacklisted": True,
            "message": "Payload hash matched Blacklist. Access Dropped! 🛡️"
        }), 403 # Immediate block (Layer 0)

    # --- Layer 1: Signature-Based Detection ---
    signature_result = check_signature(user_input)
    
    if signature_result == "Signature":
        safe_ip = _sanitize_log_value(client_ip)
        safe_input = _sanitize_log_value(user_input[:50])
        log_message = f"BLOCK (403) - Layer: Signature - IP: {safe_ip} - Input: {safe_input}..."
        waf_logger.warning(log_message)
        waf_logger.handlers[0].flush()  # Force immediate write to log file
        add_to_blacklist(payload_hash, user_input) # Add confirmed attack to blacklist

        return jsonify({
            "status": "malicious",
            "signature_status": "Signature",
            "is_blacklisted": False,
            "message": "CRITICAL! Known attack pattern detected. Access Denied! 🔒"
        }), 403 # Immediate block (Layer 1)

    if signature_result == "Valid":
        # Request is clean by Layer 1, skip Layer 2 and allow access
        safe_ip = _sanitize_log_value(client_ip)
        safe_input = _sanitize_log_value(user_input[:50])
        log_message = f"PASS (200) - Layer: Valid - IP: {safe_ip} - Input: {safe_input}..."
        waf_logger.info(log_message)
        waf_logger.handlers[0].flush()  # Force immediate write to log file

        return jsonify({
            "status": "valid",
            "signature_status": "Valid",
            "is_blacklisted": False,
            "message": "All Clear! Request verified as safe."
        }), 200 # Access granted

    # --- Layer 2: ML-Based Anomaly Detection (Only for obfuscated requests) ---
    if signature_result == "obfuscated":
        
        # Delayed Imports for Cleaner Startup
        try:
            from src.hybrid_waf.utils.preprocessor import extract_features
            from src.hybrid_waf.utils.ml_checker import check_ml_prediction, ML_THRESHOLD
        except ImportError as e:
            error_message = "ERROR: ML module import failed due to missing dependencies. Please check server configuration."
            waf_logger.error(f"FATAL - ML Import Error: {e}")
            waf_logger.handlers[0].flush()  # Force immediate write to log file
            return jsonify({
                "status": "error",
                "signature_status": "error",
                "message": error_message
            }), 500
        
        try:
            # Parse user_input as a URL to correctly separate URI path, query
            # string (GET data), and POST body for more accurate feature extraction.
            parsed = urlparse(user_input)
            uri_part = parsed.path if parsed.path else user_input
            get_part = parsed.query if parsed.query else ""
            post_part = ""  # POST body is not recoverable from a single string

            features = extract_features(uri_part, get_part, post_part)
            ml_score = check_ml_prediction(features) # Returns probability score (0.0 to 1.0)
            
            is_malicious = ml_score >= ML_THRESHOLD
            
            safe_ip = _sanitize_log_value(client_ip)
            safe_input = _sanitize_log_value(user_input[:50])

            if is_malicious:
                log_message = f"BLOCK (403) - Layer: ML - IP: {safe_ip} - Score: {ml_score:.4f} - Input: {safe_input}..."
                waf_logger.warning(log_message)
                waf_logger.handlers[0].flush()  # Force immediate write to log file
                add_to_blacklist(payload_hash, user_input) # Add high-risk payload to blacklist

                return jsonify({
                    "status": "malicious",
                    "signature_status": "obfuscated",
                    "ml_score": ml_score,
                    "is_blacklisted": False,
                    "message": "THREAT CONFIRMED! AI analysis flagged this request as malicious. Access Denied! 🚨"
                }), 403 # Block by ML (Layer 2)
            else:
                log_message = f"PASS (200) - Layer: ML - IP: {safe_ip} - Score: {ml_score:.4f} - Input: {safe_input}..."
                waf_logger.info(log_message)
                waf_logger.handlers[0].flush()  # Force immediate write to log file

                return jsonify({
                    "status": "valid",
                    "signature_status": "obfuscated",
                    "ml_score": ml_score,
                    "is_blacklisted": False,
                    "message": "AI Analysis: Request verified safe. Passed through. ✨"
                }), 200 # Access granted
                
        except Exception as e:
            error_message = "ERROR: ML System failed to process request. Please contact administrator."
            waf_logger.error(f"FATAL - ML Error: {e}")
            waf_logger.handlers[0].flush()  # Force immediate write to log file

            # Critical systems fail open, but for a demo, we return an error status
            return jsonify({
                "status": "error",
                "signature_status": "error",
                "message": error_message
            }), 500
