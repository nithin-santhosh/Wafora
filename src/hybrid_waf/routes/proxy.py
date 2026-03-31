import os
from flask import Blueprint, request, jsonify, abort
from src.hybrid_waf.utils.signature_checker import (
    check_signature, get_payload_hash, is_blacklisted, add_to_blacklist
)
import logging

# --- WAF LOGGING SETUP ---
# Use the specific WAF logger configured in app.py
waf_logger = logging.getLogger('waf')

def get_client_ip():
    """Get the real client IP address, checking proxy headers first."""
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    elif 'X-Real-IP' in request.headers:
        return request.headers['X-Real-IP']
    else:
        return request.remote_addr

proxy_bp = Blueprint('proxy', __name__)

@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
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
        client_ip = get_client_ip()
        log_message = f"BLOCK (403) - Layer: Blacklist - IP: {client_ip} - Hash: {payload_hash} - Input: {user_input[:50]}..."
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
        client_ip = get_client_ip()
        log_message = f"BLOCK (403) - Layer: Signature - IP: {client_ip} - Input: {user_input[:50]}..."
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
        client_ip = get_client_ip()
        log_message = f"PASS (200) - Layer: Valid - IP: {client_ip} - Input: {user_input[:50]}..."
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
            # Note: We use user_input for all fields in this demo for simplicity
            features = extract_features(user_input, user_input, user_input)
            ml_score = check_ml_prediction(features) # Returns probability score (0.0 to 1.0)
            
            is_malicious = ml_score >= ML_THRESHOLD
            
            if is_malicious:
                client_ip = get_client_ip()
                log_message = f"BLOCK (403) - Layer: ML - IP: {client_ip} - Score: {ml_score:.4f} - Input: {user_input[:50]}..."
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
                client_ip = get_client_ip()
                log_message = f"PASS (200) - Layer: ML - IP: {client_ip} - Score: {ml_score:.4f} - Input: {user_input[:50]}..."
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
