import re
import os
import hashlib
import threading

# --- BLACKLIST CONFIGURATION ---
# Path for the file storing hashes of known malicious payloads
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
BLACKLIST_FILE_PATH = os.path.join(BASE_DIR, 'logs', 'blacklist.txt')

# Lock that serialises all reads and writes to the blacklist file so concurrent
# requests cannot corrupt it or observe a partially-written hash.
_blacklist_lock = threading.Lock()

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
    """Checks if a payload hash exists in the blacklist file (exact-line match)."""
    if not os.path.exists(BLACKLIST_FILE_PATH):
        return False
    with _blacklist_lock:
        with open(BLACKLIST_FILE_PATH, 'r') as f:
            for line in f:
                if line.strip() == payload_hash:
                    return True
    return False

def add_to_blacklist(payload_hash: str, user_input: str):
    """Adds a payload hash to the blacklist file (thread-safe)."""
    try:
        with _blacklist_lock:
            # Avoid duplicates: check first, then append
            with open(BLACKLIST_FILE_PATH, 'r') as f:
                for line in f:
                    if line.strip() == payload_hash:
                        return  # Already present
            with open(BLACKLIST_FILE_PATH, 'a') as f:
                f.write(f"{payload_hash}\n")
    except Exception as e:
        print(f"Error writing to blacklist: {e}")


# Define known malicious patterns (expanded with additional signatures)
MALICIOUS_PATTERNS = [
    r"(?:\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bupdate\b).*?\bfrom\b",  # SQL Injection
    r"(\bscript\b|<script>)",  # XSS Attack
    r"(\balert\b|\bconsole\.log\b)",  # JavaScript-based attacks
    r"(?:--\s)|(/\*.*?\*/)|(#\s*\n)",  # Comment-based SQL Injection (contextual)
    # Additional SQL Injection Signatures
    r"(?i)union\s+select", r"(?i)drop\s+table", r"(?i)or\s+1=1", r"(?i)--\s",
    r"' or '1'='1", r"1' or '1'='1", r"1' or 1=1--", r"(?i)admin'--",
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
    # SSRF Signatures — explicit patterns
    r"file://", r"gopher://",
    # IPv4 localhost / link-local in all common notations
    r"(?i)https?://127\.",           # 127.x.x.x
    r"(?i)https?://127\.0\.0\.1",
    r"(?i)https?://0x7f",            # hex: 0x7f000001
    r"(?i)https?://0177\.",          # octal: 0177.0.0.1
    r"(?i)https?://2130706433",      # decimal: 2130706433 == 127.0.0.1
    r"(?i)https?://localhost",
    r"(?i)https?://\[::1\]",         # IPv6 loopback
    r"(?i)https?://\[::ffff:127\.",  # IPv4-mapped IPv6 loopback
    r"169\.254\.",                   # link-local / AWS IMDS
    r"169\.254\.169\.254",
    r"(?i)169\.254\.169\.254/latest/meta-data/",
    r"0x7f000001",
    r"0:0:0:0:0:ffff:7f00:1",
    r"127\.0\.0\.53",
    # Cloud metadata endpoints
    r"metadata\.google\.internal",
    r"kubernetes\.default\.svc",
    r"(?i)metadata\.",
    # Internal / private network ranges
    r"(?i)https?://10\.",
    r"(?i)https?://172\.(1[6-9]|2\d|3[01])\.",
    r"(?i)https?://192\.168\.",
    r"(?i)https?://0\.",             # 0.x.x.x  (maps to localhost on some stacks)
    # File-read shortcuts
    r"file:/etc/passwd",
    r"file:/c:/windows/system32/",
    r"ftp://",
    r"(?i)internal",
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
