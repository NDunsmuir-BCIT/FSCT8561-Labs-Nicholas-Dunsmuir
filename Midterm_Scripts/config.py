import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# only bind to localhost so the server can't be reached by random machines
HOST = "127.0.0.1"  
PORT = 8700
# force max message size
MAX_MESSAGE = 1024 
# 3 failed attempts before login closes the connection to the client
MAX_FAILURES = 3

# close idle connections after 60s so one client can't hold up the server indefinitely
IDLE_TIMEOUT = int(os.environ.get("SENTINEL_IDLE_TIMEOUT", "60"))

USERS_FILE = os.path.join(BASE_DIR, "users.json")
# fixed pcap path so the server only sets the path for the PCAP file
PCAP_FILE = os.path.join(BASE_DIR, "FSCT8561_Operation_Sentinel_Traffic.pcap")
LOG_FILE = os.path.join(BASE_DIR, "security.log")
# only letters, numbers and _ can go into a username 
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{1,32}")
OTP_RE = re.compile(r"[0-9]{6}")
MAX_PASSWORD_LEN = 128

TEST_SITE = "http://127.0.0.1:8765"
# only scan and http check localhost
ALLOWED_HOSTS = ("127.0.0.1", "localhost")
SCAN_DEFAULT_START = 8700
SCAN_DEFAULT_END = 8800
# max range per scan by the scanner
MAX_SCAN_SPAN = 100