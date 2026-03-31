import requests
import time
import json
import random
from itertools import chain

# --- Configuration ---
WAF_API_URL = "http://127.0.0.1:5000/check_request" 
# CRITICAL FIX: Aggressive delay for high-density traffic simulation
MIN_DELAY_SECONDS = 1.0  # Minimum time between requests
MAX_DELAY_SECONDS = 4.0  # Maximum time between requests (introduces natural variance)
# FIX: Set this to 1 for a 50% Attack Rate (1 Benign request for every 1 Attack request)
BENIGN_TO_MALICIOUS_RATIO = 1
# ---------------------

# --- Test Payload Categorization (unchanged) ---
BENIGN_PAYLOADS = [
    # 1-10: Benign/Valid Requests (Layer 1 Pass)
    {'user_request': 'search/products?category=electronics&price=300'},
    {'user_request': 'api/user/profile/settings'},
    {'user_request': 'GET /images/logo.png HTTP/1.1'},
    {'user_request': 'purchase/item-id/10293?qty=1'},
    {'user_request': 'blog/post/how-to-fix-database-errors'},
    {'user_request': 'checkout/step/three'},
    {'user_request': 'review-submission?rating=5&comment=great service'},
    {'user_request': 'GET /index.php?lang=en'},
    {'user_request': 'calculate_tax_for_user_id/98765'},
    {'user_request': 'query?city=new york'},
]

MALICIOUS_PAYLOADS = [
    # 11-20: Classic SQL Injection Attacks (Layer 1 Block)
    {'user_request': "1' OR '1'='1"}, 
    {'user_request': "user.php?id=1' UNION SELECT 1, @@version --"},
    {'user_request': "login?user=admin'--"},
    {'user_request': "product_id=1; EXEC xp_cmdshell('dir')"},
    {'user_request': "item?name=shoes' AND 1=1 --"},
    {'user_request': "' OR 'a'='a"},
    {'user_request': "GET /admin.jsp?user=administrator' OR '1'='1'--"},
    {'user_request': "id=20 AND 1=CONVERT(int,@@version)"},
    {'user_request': "url/fetch?param=a' having 1=1--"},
    {'user_request': "POST /login.php user=guest'; shutdown --"},
    # 21-30: Classic XSS & Command Injection (Layer 1 Block)
    {'user_request': "<script>alert('XSS')</script>"},
    {'user_request': "comment=<img src=x onerror=alert(document.cookie)>"},
    {'user_request': "document.location='http://attacker.com'"},
    {'user_request': 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='},
    {'user_request': 'username=user&password=pass | ls -la /etc/'},
    {'user_request': 'GET /page?lang=en%27%3B%20ls%20%2Fetc%2F'},
    {'user_request': 'search?q=javascript:void(0)'},
    {'user_request': 'GET /page?<iframe src=javascript:alert(1)>'},
    {'user_request': 'GET /page?<body onload="alert(1)">'},
    {'user_request': 'GET /page?<svg onload="prompt(1)">'},
]

OBFUSCATED_PAYLOADS = [
    # 31-40: Obfuscated/Evasion Techniques (Layer 2 Scan/ML Trigger)
    {'user_request': "id=1%20%4F%52%20%31%3d%31"}, # URL Encoded OR 1=1
    {'user_request': "payload=\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e"}, # Hex Encoded <script>
    {'user_request': "page?param=a' /*! OR 1=1 */ --"}, # MySQL Comment Evasion
    {'user_request': "product?id=1' UNION select CHAR(117,115,101,114) --"}, # SQL CHAR() Function
    {'user_request': 'POST /data?q=sleep(10)'}, # Time-based attack indicator
    {'user_request': 'GET /file.php?file=file%3a%2f%2f%2fetc%2fpasswd'}, # File URI SSRF attempt
    {'user_request': 'GET /internal?host=http://127.0.0.1'}, # Localhost/SSRF probe
    {'user_request': "search?q=1%20or%201=1%20--%20"}, # Partially encoded SQLi
    {'user_request': "login?user=admin /* and 1=1 */"}, # Comment-based SQLi evasion
    {'user_request': "product?id=1; WAITFOR DELAY '0:0:10'"}, # MS SQL time delay (Signature-based)
]
# --- End Test Payloads ---

ATTACK_PAYLOADS = list(chain(MALICIOUS_PAYLOADS, OBFUSCATED_PAYLOADS))

# --- Global Counters (unchanged) ---
TOTAL_SENT = 0
TOTAL_BLOCKED = 0
# -----------------------------------

def get_random_payload():
    """Returns a payload, strongly biased towards benign traffic."""
    
    if random.randint(1, BENIGN_TO_MALICIOUS_RATIO + 1) <= BENIGN_TO_MALICIOUS_RATIO:
        return random.choice(BENIGN_PAYLOADS)
    else:
        return random.choice(ATTACK_PAYLOADS)


def analyze_request(data):
    """Sends a single request to the WAF API and processes the response."""
    global TOTAL_SENT, TOTAL_BLOCKED
    TOTAL_SENT += 1
    
    try:
        response = requests.post(WAF_API_URL, json=data)
        
        # Manually check for 403 (BLOCKED)
        if response.status_code == 403:
            TOTAL_BLOCKED += 1
            result = response.json()
            status = "BLOCKED (403)"
            verdict = result.get('message', 'Access Denied by WAF')
        elif response.status_code == 200:
            result = response.json()
            status = result['status'].upper()
            verdict = result.get('message', 'Processing...')
        else:
            response.raise_for_status() # Raise for any other unexpected error

        # Further refinement of the verdict message for clarity
        if 'signature_status' in result:
             verdict = f"Layer {result['signature_status'].upper()}: {result.get('message', 'Verdict Cleared')}"

        if result.get('is_blacklisted'):
            verdict = f"Layer BLACKLIST: {result.get('message', 'Dropped!')}"
        
        # --- Console Output ---
        block_rate = (TOTAL_BLOCKED / TOTAL_SENT) * 100 if TOTAL_SENT > 0 else 0.0
        
        print("-" * 50)
        print(f"INPUT: {data['user_request'][:50]}...")
        print(f"WAF STATUS: {status} ({response.status_code})")
        print(f"VERDICT DETAIL: {verdict.replace('<br>', ' ')}")
        print(f"TRAFFIC: Sent: {TOTAL_SENT} | Blocked: {TOTAL_BLOCKED} | Block Rate: {block_rate:.2f}%")
        # --- End Console Output ---

    except requests.exceptions.RequestException as e:
        print("-" * 50)
        print(f"Error connecting to WAF: {e}")
        print("ACTION: Ensure your Flask application is running!")


if __name__ == "__main__":
    print("=" * 50)
    print("--- Starting Continuous WAF Traffic Simulation ---")
    print(f"Ratio (Benign:Attack) is {BENIGN_TO_MALICIOUS_RATIO}:1. (Attack Concentration: 50%)")
    print(f"Traffic will run indefinitely until interrupted (Ctrl+C).")
    print("=" * 50)
    time.sleep(2)
    
    try:
        while True:
            payload = get_random_payload()
            analyze_request(payload)
            
            # Use a random delay for a more natural traffic pattern
            delay = random.uniform(MIN_DELAY_SECONDS, MAX_DELAY_SECONDS)
            time.sleep(delay)
            
    except KeyboardInterrupt:
        print("\n\n" + "=" * 50)
        print("      Traffic Simulation Stopped by User.")
        print(f"      Final Traffic Sent: {TOTAL_SENT} | Blocked: {TOTAL_BLOCKED}")
        print("=" * 50)