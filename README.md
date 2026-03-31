# Wafora - AI-Powered Web Security

Wafora is a hybrid Web Application Firewall (WAF) leveraging both signature-based rules and Machine Learning to detect and block malicious web requests, including advanced obfuscation techniques.

---
## Features

- **Layer 0 (Blacklist Check):** Immediate block of known malicious payload hashes for lightning-fast mitigation.

- **Layer 1 (Signature Detection):** Real-time pattern matching against SQL Injection (SQLi), Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), and other common attack vectors.

- **Layer 2 (ML Anomaly Detection):** Deep learning evaluation of obfuscated payloads. Extracts features like Shannon entropy, URI length, and character density to block novel evasion techniques.

---
## Installation

1. Verify Python 3.8+ is installed.

2. Clone this repository to your local machine.

3. Install dependencies:
   
```
pip install -r requirements.txt
```
---
## Running the Application

Start the Flask server from the root directory:

```
python app.py
```
*Note: Make sure your `ml_model.pkl` is located in `src/hybrid_waf/models/` before starting.*

The web dashboard usually binds to `http://0.0.0.0:5000`.

---
## Testing the Firewall

A continuous traffic simulator is provided to test the application's response to various attack vectors and benign traffic:

```
python test_automation.py
```

## Logs

All detections and firewall decisions are logged to `logs/detections.log`. Confirmed malicious payload hashes are added to `logs/blacklist.txt`.
