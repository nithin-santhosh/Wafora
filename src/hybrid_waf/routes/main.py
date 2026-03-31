import os
import re
import json
import shutil
import tempfile
import logging
import uuid
from collections import deque
from flask import Blueprint, render_template, send_file, jsonify, make_response, abort, current_app

# --- Blueprint registration ---
main_bp = Blueprint('main', __name__)

# --- Unified base directory path ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
LOG_FILE_PATH = os.path.join(BASE_DIR, 'logs', 'detections.log')


# --- Helper: Add no-cache headers for API responses ---
def prevent_caching(response):
    """Adds headers to ensure browser fetches fresh data (no client-side caching)."""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Content-Type'] = 'application/json'
    return response


# --- Root routes ---
@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.route('/home')
def home():
    return render_template('home.html')


# --- Download detections report ---
@main_bp.route('/download-detections-report')
def download_report():
    """Safely sends the detections log file for download without causing stream interruptions."""
    try:
        detections_file_path = LOG_FILE_PATH
        log_dir = os.path.dirname(detections_file_path)

        # Ensure log directory exists
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        # If log file doesn't exist, create a placeholder
        if not os.path.exists(detections_file_path):
            with open(detections_file_path, 'w') as f:
                f.write("Wafora: No detections recorded yet.\n")

        # Create a temporary copy of the log file to prevent file lock/read errors
        tmp_dir = tempfile.gettempdir()
        tmp_copy_path = os.path.join(tmp_dir, f"wafora_detections_copy_{uuid.uuid4().hex}.log")
        shutil.copyfile(detections_file_path, tmp_copy_path)

        # Send the copy instead of the live file
        return send_file(
            tmp_copy_path,
            mimetype='text/plain',
            as_attachment=True,
            download_name='wafora_detections_report.log',
            conditional=False  # ensures full download even for large files
        )

    except Exception as e:
        current_app.logger.error(f"Error preparing detections report: {e}")
        abort(500, description="Error preparing detections report for download.")


# --- API: Live log stream ---
@main_bp.route('/api/live-logs', methods=['GET'])
def get_live_logs():
    """Reads the last N lines of the detections log file and returns them as JSON."""
    MAX_LINES = 100
    logs = deque(maxlen=MAX_LINES)

    if os.path.exists(LOG_FILE_PATH):
        try:
            # FIX: Read the entire file content at once. This often ensures the OS/Python 
            # flushes any stale buffer and retrieves the freshest data from disk.
            with open(LOG_FILE_PATH, 'r') as f:
                content = f.read()

            if content:
                # Split content into lines and strip them before appending to deque
                for line in content.splitlines():
                    logs.append(line.strip())
                    
        except Exception:
            # Return an error message if file can't be read
            response = make_response(jsonify({"logs": ["ERROR: Could not read log file."]}))
            return prevent_caching(response)

    response = make_response(jsonify({"logs": list(logs)}))
    return prevent_caching(response)


# --- API: WAF statistics (pie chart) ---
@main_bp.route('/api/stats', methods=['GET'])
def get_stats():
    """Reads the detections log and calculates stats for WAF dashboard pie chart."""
    stats = {
        'valid': 0,
        'malicious_signature': 0,
        'malicious_ml': 0
    }

    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if re.search(r'BLOCK \(403\).* - Layer: Signature', line, re.IGNORECASE) or \
                       re.search(r'BLOCK \(403\).* - Layer: Blacklist', line, re.IGNORECASE):
                        stats['malicious_signature'] += 1
                    elif re.search(r'BLOCK \(403\).* - Layer: ML', line, re.IGNORECASE):
                        stats['malicious_ml'] += 1
                    elif re.search(r'PASS \(200\).*', line, re.IGNORECASE):
                        stats['valid'] += 1
        except Exception as e:
            current_app.logger.warning(f"Error reading stats: {e}")

    response = make_response(jsonify(stats))
    return prevent_caching(response)