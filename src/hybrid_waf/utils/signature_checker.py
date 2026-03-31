import re
import os
import hashlib

# --- BLACKLIST CONFIGURATION ---
# Path for the file storing hashes of known malicious payloads
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
BLACKLIST_FILE_PATH = os.path.join(BASE_DIR, 'logs', 'blacklist.txt')

def setup_blacklist():
    """Ensures the logs directory and blacklist file exist."""
    log_dir = os.path.dirname(BLACKLIST_FILE_PATH)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    if not os.path.exists(BLACKLIST_FILE_PATH):
        with open(BLACKLIST_FILE_PATH, 'w') as f:
            f.write("# Wafora Blacklist (SHA256 Payload Hashes)\n")

# Call setup immediately to ensure files exist
setup_blacklist()

def get_payload_hash(user_input: str) -> str:
    """Calculates the SHA256 hash of the normalized user input."""
    normalized_input = user_input.strip().lower()
    return hashlib.sha256(normalized_input.encode('utf-8')).hexdigest()

def is_blacklisted(payload_hash: str) -> bool:
    """Checks if a payload hash exists in the blacklist file."""
    if not os.path.exists(BLACKLIST_FILE_PATH):
        return False
    with open(BLACKLIST_FILE_PATH, 'r') as f:
        return payload_hash in f.read()

def add_to_blacklist(payload_hash: str, user_input: str):
    """Adds a payload hash and the original input to the blacklist file."""
    try:
        with open(BLACKLIST_FILE_PATH, 'a') as f:
            f.write(f"{payload_hash}\n")
    except Exception as e:
        print(f"Error writing to blacklist: {e}")


# Define known malicious patterns (expanded with additional signatures)
MALICIOUS_PATTERNS = [
    r"(?:\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bupdate\b).*?\bfrom\b",  # SQL Injection
    r"(\bscript\b|<script>)",  # XSS Attack
    r"(\balert\b|\bconsole\.log\b)",  # JavaScript-based attacks
    r"(?:--)|(/\*.*?\*/)|(#.*?\n)",  # Comment-based SQL Injection
    # Additional SQL Injection Signatures
    r"(?i)union\s+select", r"(?i)drop\s+table", r"(?i)or\s+1=1", r"--", 
    r"' or '1'='1", r"1' or '1'='1", r"1' or 1=1--", r"(?i)admin'--", r"#",
    r"/\*.*\*/", r"' and '1'='1", r"' and sleep\(", r"(?i)or\s+sleep\(",
    r"'; drop table users;--", r"'; exec xp_cmdshell\(", r"(?i)or\s+1=1--", 
    r"(?i)waitfor\s+delay", r"(?i)select\s+\*", r"';shutdown --", 
    r"' union all select", r"' and benchmark\(", r"' having 1=1--", 
    r"' and ascii\(", r"' group by columnnames having 1=1--", 
    r"(?i)select username", 
    r"(?i)select password", r"'; waitfor delay '0:0:10'--", 
    r"' OR '1'='1'--", r"(?i)select\s+@@version", r"(?i)select\s+@@datadir", 
    r"(?i)select\s+load_file", r"(?i)select\s+user\(\)", 
    r"(?i)select\s+database\(\)", r"\" OR \"1\"=\"1", r"\' OR \'1\'=\'1",
    # Additional XSS Signatures
    r"(?i)<script>", r"(?i)<img src=", r"(?i)onerror=", r"(?i)alert\(", 
    r"(?i)document\.cookie", r"javascript:", r"(?i)<iframe>", r"(?i)<svg>", 
    r"(?i)onmouseover=", r"(?i)onload=", r"(?i)eval\(", r"settimeout\(", 
    r"setinterval\(", r"(?i)innerhtml=", r"(?i)srcdoc=", 
    r"(?i)<link rel=stylesheet href=", r"fetch\(", r"xhr\.open\(", 
    r"window\.location=", r"self\.location=", r"(?i)prompt\(", 
    r"constructor\.constructor\(", r"String\.fromCharCode\(", r"&#x", 
    r"&lt;script&gt;", r"(?i)<body onload=", r"onfocus=", r"onblur=", 
    r"onclick=", r"onkeydown=", r"onkeyup=", r"src=javascript:", 
    r"data:text/html;base64", r"(?i)<embed>", r"(?i)confirm\(",
    # Additional SSRF Signatures
    r"file://", r"gopher://", r"ftp://", r"http://127\.0\.0\.1", 
    r"http://localhost", r"169\.254\.", r"internal", 
    r"metadata\.google\.internal", r"aws", r"azure", 
    r"kubernetes\.default\.svc", r"169\.254\.169\.254", r"127\.0\.0\.53", 
    r"metadata\.", r"0x7f000001", r"0:0:0:0:0:ffff:7f00:1", 
    r"169\.254\.169\.254/latest/meta-data/", r"file:/etc/passwd", 
    r"file:/c:/windows/system32/", r"http://0x7f000001", 
    r"localhost:8080", r"127\.0\.0\.1:3306", r"http://10\.", 
    r"http://192\.168\."
]

# Define obfuscation patterns (suspicious but not explicit attacks)
OBFUSCATION_PATTERNS = [
    r"(%[0-9A-Fa-f]{2})+",  # URL encoding
    r"(\\x[0-9A-Fa-f]{2})+",  # Hex encoding
    r"(\bchar\b|\bconcat\b|\bsubstr\b)",  # SQL obfuscation functions
    r"(\bbase64_decode\b|\bbase64_encode\b)",  # Base64 encoding
    r"(\\u[0-9A-Fa-f]{4})+",  # Unicode escape sequences
    r"(\bfromCharCode\b)",  # JavaScript obfuscation
    r"(\bROT13\b)",  # ROT13 encoding
    r"(\bdecodeURIComponent\b|\bencodeURIComponent\b)",  # URI encoding
    r"(\bhexToInt\b|\bcharCodeAt\b)",  # Character conversion tricks
    r"(\\bXOR\\b|\bXOR\b)",  # XOR encoding
    r"(\bmd5\b|\bsha1\b|\bsha256\b)",  # Hash-based obfuscation
    r"(\bblind_sql\b|\btime_delay\b)",  # Blind SQL injection techniques
    r"(\bcase when\b|\bcase\b|\bthen\b)",  # SQL CASE obfuscation
    r"(?:--)|(/\*.*?\*/)|(#.*?\n)",  # Comment-based SQL obfuscation
    r"xmlhttprequest", r"cross-site", r"token=", r"access_token=", r"xsrf-token", 
    r"csrf-token", r"application/x-www-form-urlencoded", r"submitform\(", r"credentials=", 
    r"(?i)<input type=hidden", r"Authorization: Bearer", r"(?i)<form method="
]

def check_signature(user_input: str):
    """
    Checks if the user request matches malicious or obfuscation patterns.
    Returns:
        - "Signature" if it's a direct attack
        - "obfuscated" if it looks suspicious (Layer 2 trigger)
        - "Valid" if nothing is detected
    """
    user_input = " ".join(user_input.split())  # Normalize input
    
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return "Signature"  # Directly detected attack (Layer 1)
    
    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return "obfuscated"  # Suspicious (Layer 2 Trigger)

    return "Valid"  # Safe by Layer 1 check
