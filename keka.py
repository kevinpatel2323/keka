import requests
import json
import time
import base64
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, parse_qs
import schedule
import logging
import pytz
import os
import sys

# Redis import attempt
try:
    import redis
except ImportError:
    redis = None

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Constants
IST = pytz.timezone('Asia/Kolkata')
TOKEN_FILE = 'keka_tokens.json'
REDIS_KEY = 'keka_tokens'

# Redis connection
kv = None
redis_url = os.environ.get("KV_URL") or os.environ.get("REDIS_URL")
if redis_url:
    try:
        kv = redis.from_url(redis_url)
        # Verify connection
        kv.ping()
        logging.info("Connected to Redis/Vercel KV")
    except Exception as e:
        logging.error(f"Failed to connect to Redis: {e}")
        kv = None

class KekaAttendance:
    def __init__(self):
        self.base_url = "https://alchemy.keka.com"
        self.auth_url = "https://app.keka.com"
        self.client_id = "987cc971-fc22-4454-99f9-16c078fa7ff6"
        self.redirect_uri = "https://alchemy.keka.com"
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        code_verifier = code_verifier.replace('=', '').replace('+', '-').replace('/', '_')
        
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '').replace('+', '-').replace('/', '_')
        
        return code_verifier, code_challenge
    
    def get_authorization_url(self):
        """Generate OAuth authorization URL with PKCE"""
        code_verifier, code_challenge = self.generate_pkce_pair()
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid kekahr.api hiro.api offline_access',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{self.auth_url}/connect/authorize?{urlencode(params)}"
        return auth_url, code_verifier
    
    def exchange_code_for_token(self, authorization_code, code_verifier):
        """Exchange authorization code for access token"""
        token_url = f"{self.auth_url}/connect/token"
        
        data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': code_verifier,
            'client_id': self.client_id,
            'client_secret': ''
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': self.user_agent
        }
        
        try:
            response = requests.post(token_url, data=data, headers=headers)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            self.refresh_token = token_data.get('refresh_token')
            self.token_expiry = self.decode_jwt_expiry(self.access_token)
            
            self.save_tokens()
            return True
        except Exception as e:
            logging.error(f"Error exchange_code_for_token: {e}")
            return False
            
    def decode_jwt_expiry(self, token):
        """Decode JWT to get expiry time"""
        try:
            payload = token.split('.')[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            return data.get('exp')
        except Exception as e:
            logging.error(f"Error decoding token: {e}")
            return None
    
    def is_token_expired(self):
        """Check if token is expired or expires soon"""
        if not self.token_expiry:
            return True
        return time.time() > (self.token_expiry - 300)
    
    def refresh_access_token(self):
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            logging.error("No refresh token available")
            return False
        
        token_url = f"{self.auth_url}/connect/token"
        
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        
        try:
            response = requests.post(token_url, data=data, headers=headers)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            if 'refresh_token' in token_data:
                self.refresh_token = token_data['refresh_token']
            self.token_expiry = self.decode_jwt_expiry(self.access_token)
            
            self.save_tokens()
            logging.info("Token refreshed successfully")
            return True
        except Exception as e:
            logging.error(f"Error refreshing token: {e}")
            return False
    
    def save_tokens(self):
        """Save tokens to Redis (if available) or file"""
        tokens = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_expiry': self.token_expiry
        }
        
        if kv:
            try:
                kv.set(REDIS_KEY, json.dumps(tokens))
                logging.info("Tokens saved to Redis")
            except Exception as e:
                logging.error(f"Failed to save tokens to Redis: {e}")
        else:
            with open(TOKEN_FILE, 'w') as f:
                json.dump(tokens, f)
            logging.info("Tokens saved to file")
    
    def load_tokens(self):
        """Load tokens from Redis (if available) or file"""
        tokens = None
        
        if kv:
            try:
                data = kv.get(REDIS_KEY)
                if data:
                    tokens = json.loads(data)
                    logging.info("Tokens loaded from Redis")
                else:
                    logging.warning("No tokens found in Redis")
            except Exception as e:
                logging.error(f"Failed to load tokens from Redis: {e}")
        
        if not tokens:
            try:
                with open(TOKEN_FILE, 'r') as f:
                    tokens = json.load(f)
                    logging.info("Tokens loaded from file")
            except FileNotFoundError:
                pass
            except Exception as e:
                 logging.error(f"Error loading tokens from file: {e}")

        if tokens:
            self.access_token = tokens.get('access_token')
            self.refresh_token = tokens.get('refresh_token')
            self.token_expiry = tokens.get('token_expiry')
            return True
        return False
    
    def clock_action(self, action_type="in"):
        """Perform clock in or clock out"""
        if self.is_token_expired():
            logging.info("Token expired, refreshing...")
            if not self.refresh_access_token():
                logging.error("Failed to refresh token. Please re-authenticate.")
                return False
        
        url = f"{self.base_url}/k/attendance/api/mytime/attendance/remoteclockin"
        
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json; charset=UTF-8',
            'Origin': self.base_url,
            'Referer': f'{self.base_url}/',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        }
        
        original_punch_status = 0 if action_type.lower() == "in" else 1
        note = "In" if action_type.lower() == "in" else "Out"
        
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "attendanceLogSource": 1,
            "locationAddress": None,
            "manualClockinType": 3,
            "note": note,
            "originalPunchStatus": original_punch_status
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            logging.info(f"Clock {action_type.upper()} successful at {datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S %Z')}")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Clock {action_type.upper()} failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"Response: {e.response.text}")
            return False
    
    def clock_in(self):
        return self.clock_action("in")
    
    def clock_out(self):
        return self.clock_action("out")

# --- Scheduler / Run Logic ---

def is_weekday():
    """Check if today is a weekday in IST"""
    return datetime.now(IST).weekday() < 5  # Monday = 0, Friday = 4

def run_clock_in():
    """Executed by Cron"""
    if is_weekday():
        logging.info("Assuming weekday check passed (or forced). Attempting clock in...")
        keka = KekaAttendance()
        if keka.load_tokens():
            return keka.clock_in()
        else:
            logging.error("No tokens found.")
            return False
    else:
        logging.info("Not a weekday. Skipping.")
        return False

def run_clock_out():
    """Executed by Cron"""
    if is_weekday():
        logging.info("Assuming weekday check passed (or forced). Attempting clock out...")
        keka = KekaAttendance()
        if keka.load_tokens():
            return keka.clock_out()
        else:
            logging.error("No tokens found.")
            return False
    else:
        logging.info("Not a weekday. Skipping.")
        return False

# --- CLI Setup Logic ---

def initial_setup():
    """Initial authentication setup"""
    keka = KekaAttendance()
    print("\n=== Keka Attendance Initial Setup ===\n")
    auth_url, code_verifier = keka.get_authorization_url()
    
    print(f"\n1. Open this URL in your browser:\n\n{auth_url}\n")
    print("2. Login and copy the 'code' parameter.")
    authorization_code = input("\nPaste the code here: ").strip()
    
    if keka.exchange_code_for_token(authorization_code, code_verifier):
        print("\n✓ Setup successful!")
        if kv:
            print("Tokens saved to Redis (Vercel KV).")
            # Also save to file for backup/verification if run locally
            with open(TOKEN_FILE, 'w') as f:
                 # Need to manually get from object as save_tokens handles dual logic
                 tokens = {
                    'access_token': keka.access_token,
                    'refresh_token': keka.refresh_token,
                    'token_expiry': keka.token_expiry
                 }
                 json.dump(tokens, f)
            print("Tokens also saved to local file 'keka_tokens.json'.")
        else:
            print("Tokens saved to local file 'keka_tokens.json'.")
    else:
        print("\n✗ Setup failed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "setup":
            initial_setup()
        elif command == "test-in":
            run_clock_in()
        elif command == "test-out":
            run_clock_out()
        else:
            print("Commands: setup, test-in, test-out")
    else:
        print("Usage: python keka.py [setup|test-in|test-out]")