# backend/app/auth.py
"""
Authentication module for the Intrusion Detection System.
Provides JWT-based authentication with user management.
Includes brute-force attack detection and login rate limiting.
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Callable
from pydantic import BaseModel, Field
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from collections import defaultdict
from dataclasses import dataclass, field
import json
import logging

logger = logging.getLogger(__name__)

# --- Configuration ---
# Secret key for JWT (in production, use environment variable)
SECRET_KEY = os.getenv("IDS_SECRET_KEY", secrets.token_hex(32))
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))
USERS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "users.json")

# Login Rate Limiting Configuration
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # Max failed attempts before lockout
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))  # Lockout duration
LOGIN_ATTEMPT_WINDOW = int(os.getenv("LOGIN_ATTEMPT_WINDOW", "5"))  # Window in minutes to track attempts

# Ensure data directory exists
os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)


# =============================================================================
# LOGIN RATE LIMITING & BRUTE FORCE DETECTION
# =============================================================================

@dataclass
class LoginAttemptTracker:
    """Track login attempts for an IP address"""
    ip: str
    failed_attempts: int = 0
    successful_attempts: int = 0
    first_attempt: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_attempt: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    locked_until: Optional[datetime] = None
    attempted_usernames: List[str] = field(default_factory=list)
    
    def is_locked(self) -> bool:
        """Check if IP is currently locked out"""
        if self.locked_until is None:
            return False
        if datetime.now(timezone.utc) > self.locked_until:
            # Lockout expired, reset
            self.locked_until = None
            self.failed_attempts = 0
            self.attempted_usernames = []
            return False
        return True
    
    def time_until_unlock(self) -> Optional[int]:
        """Get seconds until unlock, None if not locked"""
        if not self.is_locked():
            return None
        return int((self.locked_until - datetime.now(timezone.utc)).total_seconds())
    
    def to_dict(self) -> Dict:
        return {
            'ip': self.ip,
            'failed_attempts': self.failed_attempts,
            'successful_attempts': self.successful_attempts,
            'first_attempt': self.first_attempt.isoformat(),
            'last_attempt': self.last_attempt.isoformat(),
            'is_locked': self.is_locked(),
            'locked_until': self.locked_until.isoformat() if self.locked_until else None,
            'time_until_unlock': self.time_until_unlock(),
            'attempted_usernames': list(set(self.attempted_usernames[-10:]))  # Last 10 unique
        }


class LoginRateLimiter:
    """
    Rate limiter for login attempts.
    Detects brute force attacks and locks out IPs.
    """
    
    def __init__(self):
        self.trackers: Dict[str, LoginAttemptTracker] = {}
        self.alerts: List[Dict] = []
        self.alert_callbacks: List[Callable] = []
        
        # Thresholds
        self.max_attempts = LOGIN_MAX_ATTEMPTS
        self.lockout_minutes = LOGIN_LOCKOUT_MINUTES
        self.attempt_window_minutes = LOGIN_ATTEMPT_WINDOW
        
        # Statistics
        self.total_blocked_attempts = 0
        self.total_lockouts = 0
    
    def add_alert_callback(self, callback: Callable):
        """Add callback for login attack alerts"""
        self.alert_callbacks.append(callback)
    
    def _trigger_alert(self, alert: Dict):
        """Trigger alert callbacks"""
        self.alerts.append(alert)
        # Keep last 500 alerts
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-500:]
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in login alert callback: {e}")
    
    def _get_tracker(self, ip: str) -> LoginAttemptTracker:
        """Get or create tracker for IP"""
        if ip not in self.trackers:
            self.trackers[ip] = LoginAttemptTracker(ip=ip)
        return self.trackers[ip]
    
    def _cleanup_old_trackers(self):
        """Remove old trackers to prevent memory bloat"""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=1)
        
        to_remove = []
        for ip, tracker in self.trackers.items():
            if tracker.last_attempt < cutoff and not tracker.is_locked():
                to_remove.append(ip)
        
        for ip in to_remove:
            del self.trackers[ip]
    
    def check_rate_limit(self, ip: str) -> Dict:
        """
        Check if IP is allowed to attempt login.
        Returns dict with 'allowed', 'reason', 'retry_after' (seconds)
        """
        tracker = self._get_tracker(ip)
        
        # Check if locked
        if tracker.is_locked():
            self.total_blocked_attempts += 1
            return {
                'allowed': False,
                'reason': 'IP temporarily locked due to too many failed login attempts',
                'retry_after': tracker.time_until_unlock(),
                'failed_attempts': tracker.failed_attempts
            }
        
        return {
            'allowed': True,
            'failed_attempts': tracker.failed_attempts,
            'attempts_remaining': self.max_attempts - tracker.failed_attempts
        }
    
    def record_attempt(self, ip: str, username: str, success: bool) -> Dict:
        """
        Record a login attempt.
        Returns detection result with any alerts triggered.
        """
        tracker = self._get_tracker(ip)
        now = datetime.now(timezone.utc)
        tracker.last_attempt = now
        
        # Track attempted username
        tracker.attempted_usernames.append(username)
        
        if success:
            # Successful login - reset failed counter
            tracker.successful_attempts += 1
            old_failed = tracker.failed_attempts
            tracker.failed_attempts = 0
            tracker.locked_until = None
            
            # Alert if there were previous failed attempts (possible targeted attack that succeeded)
            if old_failed >= 3:
                alert = {
                    'type': 'login_success_after_failures',
                    'severity': 'MEDIUM',
                    'ip': ip,
                    'username': username,
                    'previous_failures': old_failed,
                    'timestamp': now.isoformat(),
                    'message': f'Successful login after {old_failed} failed attempts - possible compromised credentials'
                }
                self._trigger_alert(alert)
            
            return {
                'success': True,
                'message': 'Login successful'
            }
        
        # Failed login
        tracker.failed_attempts += 1
        
        result = {
            'success': False,
            'failed_attempts': tracker.failed_attempts,
            'max_attempts': self.max_attempts
        }
        
        # Check if we need to lockout
        if tracker.failed_attempts >= self.max_attempts:
            tracker.locked_until = now + timedelta(minutes=self.lockout_minutes)
            self.total_lockouts += 1
            
            # Generate brute force alert
            alert = {
                'type': 'brute_force_detected',
                'severity': 'HIGH',
                'ip': ip,
                'failed_attempts': tracker.failed_attempts,
                'attempted_usernames': list(set(tracker.attempted_usernames[-20:])),
                'locked_until': tracker.locked_until.isoformat(),
                'lockout_minutes': self.lockout_minutes,
                'timestamp': now.isoformat(),
                'message': f'Brute force attack detected from {ip} - {tracker.failed_attempts} failed attempts. IP locked for {self.lockout_minutes} minutes.'
            }
            self._trigger_alert(alert)
            logger.warning(f"🚨 BRUTE FORCE ATTACK: IP {ip} locked after {tracker.failed_attempts} failed login attempts")
            
            result['locked'] = True
            result['locked_until'] = tracker.locked_until.isoformat()
            result['retry_after'] = self.lockout_minutes * 60
            result['message'] = f'Too many failed attempts. IP locked for {self.lockout_minutes} minutes.'
        
        # Alert on multiple failures (before lockout)
        elif tracker.failed_attempts == 3:
            alert = {
                'type': 'login_failures_warning',
                'severity': 'LOW',
                'ip': ip,
                'failed_attempts': tracker.failed_attempts,
                'attempted_usernames': list(set(tracker.attempted_usernames[-10:])),
                'timestamp': now.isoformat(),
                'message': f'Multiple failed login attempts from {ip} - {self.max_attempts - tracker.failed_attempts} attempts remaining before lockout'
            }
            self._trigger_alert(alert)
        
        # Detect credential stuffing (many different usernames)
        unique_usernames = len(set(tracker.attempted_usernames[-20:]))
        if unique_usernames >= 5 and tracker.failed_attempts >= 5:
            alert = {
                'type': 'credential_stuffing_detected',
                'severity': 'CRITICAL',
                'ip': ip,
                'unique_usernames': unique_usernames,
                'failed_attempts': tracker.failed_attempts,
                'timestamp': now.isoformat(),
                'message': f'Credential stuffing attack detected from {ip} - {unique_usernames} different usernames attempted'
            }
            self._trigger_alert(alert)
            logger.warning(f"🚨 CREDENTIAL STUFFING: IP {ip} tried {unique_usernames} different usernames")
        
        # Cleanup periodically
        if len(self.trackers) > 100:
            self._cleanup_old_trackers()
        
        return result
    
    def get_statistics(self) -> Dict:
        """Get login rate limiting statistics"""
        locked_ips = [ip for ip, t in self.trackers.items() if t.is_locked()]
        
        return {
            'total_tracked_ips': len(self.trackers),
            'currently_locked': len(locked_ips),
            'locked_ips': locked_ips,
            'total_lockouts': self.total_lockouts,
            'total_blocked_attempts': self.total_blocked_attempts,
            'recent_alerts': len([a for a in self.alerts 
                                 if datetime.fromisoformat(a['timestamp']) > 
                                    datetime.now(timezone.utc) - timedelta(hours=1)]),
            'thresholds': {
                'max_attempts': self.max_attempts,
                'lockout_minutes': self.lockout_minutes,
                'attempt_window_minutes': self.attempt_window_minutes
            }
        }
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent login attack alerts"""
        return self.alerts[-limit:]
    
    def get_ip_status(self, ip: str) -> Optional[Dict]:
        """Get status for specific IP"""
        if ip in self.trackers:
            return self.trackers[ip].to_dict()
        return None
    
    def unlock_ip(self, ip: str) -> bool:
        """Manually unlock an IP"""
        if ip in self.trackers:
            self.trackers[ip].locked_until = None
            self.trackers[ip].failed_attempts = 0
            logger.info(f"Manually unlocked IP: {ip}")
            return True
        return False
    
    def get_all_trackers(self, limit: int = 50) -> List[Dict]:
        """Get all IP trackers sorted by failed attempts"""
        sorted_trackers = sorted(
            self.trackers.values(),
            key=lambda t: (t.is_locked(), t.failed_attempts),
            reverse=True
        )
        return [t.to_dict() for t in sorted_trackers[:limit]]
    
    def get_failed_logins_for_ip(self, ip: str) -> int:
        """Get failed login count for a specific IP - used by ML model"""
        if ip in self.trackers:
            return self.trackers[ip].failed_attempts
        return 0
    
    def get_login_stats_for_ml(self, ip: str) -> Dict:
        """Get comprehensive login stats for ML feature extraction"""
        if ip not in self.trackers:
            return {
                'num_failed_logins': 0,
                'is_locked': False,
                'unique_usernames_tried': 0,
                'is_guest_login': 0,
                'is_host_login': 0,
                'su_attempted': 0
            }
        
        tracker = self.trackers[ip]
        unique_users = len(set(tracker.attempted_usernames))
        
        # Check for privilege escalation attempts (root, admin, sudo in usernames)
        priv_esc_attempts = sum(1 for u in tracker.attempted_usernames 
                                if any(x in u.lower() for x in ['root', 'admin', 'sudo', 'su', 'administrator']))
        
        # Check for guest login attempts
        guest_attempts = sum(1 for u in tracker.attempted_usernames 
                            if any(x in u.lower() for x in ['guest', 'anonymous', 'test', 'demo']))
        
        return {
            'num_failed_logins': tracker.failed_attempts,
            'is_locked': tracker.is_locked(),
            'unique_usernames_tried': unique_users,
            'is_guest_login': 1 if guest_attempts > 0 else 0,
            'is_host_login': 1 if tracker.successful_attempts > 0 else 0,
            'su_attempted': 1 if priv_esc_attempts > 0 else 0,
            'root_shell_attempted': priv_esc_attempts
        }


# Create global login rate limiter instance
login_rate_limiter = LoginRateLimiter()


# --- Pydantic Models ---

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    role: str = Field("viewer", description="User role: admin, operator, viewer")


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="Password (min 6 characters)")


class UserLogin(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class UserResponse(UserBase):
    id: str
    created_at: str
    last_login: Optional[str] = None
    is_active: bool = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserResponse


class TokenPayload(BaseModel):
    sub: str  # username
    exp: int  # expiration timestamp
    role: str
    iat: int  # issued at


# --- Password Hashing ---

def hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        salt, pwd_hash = hashed.split(":")
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except (ValueError, AttributeError):
        return False


# --- Simple JWT Implementation (no external dependencies) ---

def base64url_encode(data: bytes) -> str:
    """Base64 URL-safe encoding without padding"""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(data: str) -> bytes:
    """Base64 URL-safe decoding"""
    import base64
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_token(username: str, role: str) -> tuple[str, int]:
    """
    Create a JWT-like token.
    Returns (token, expiration_timestamp)
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    exp_timestamp = int(exp.timestamp())
    
    # Header
    header = {"alg": "HS256", "typ": "JWT"}
    
    # Payload
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": exp_timestamp
    }
    
    # Encode
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    
    # Sign
    message = f"{header_b64}.{payload_b64}"
    signature = hashlib.sha256((message + SECRET_KEY).encode()).hexdigest()
    signature_b64 = base64url_encode(bytes.fromhex(signature))
    
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return token, exp_timestamp


def verify_token(token: str) -> Optional[Dict]:
    """
    Verify JWT token and return payload if valid.
    Returns None if invalid or expired.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hashlib.sha256((message + SECRET_KEY).encode()).hexdigest()
        expected_sig_b64 = base64url_encode(bytes.fromhex(expected_sig))
        
        if signature_b64 != expected_sig_b64:
            logger.warning("Token signature verification failed")
            return None
        
        # Decode payload
        payload = json.loads(base64url_decode(payload_b64))
        
        # Check expiration
        if payload.get("exp", 0) < datetime.now(timezone.utc).timestamp():
            logger.warning("Token expired")
            return None
        
        return payload
        
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None


# --- User Storage ---

class UserStore:
    """Simple file-based user storage"""
    
    def __init__(self):
        self.users: Dict[str, Dict] = {}
        self.load_users()
        self._ensure_default_admin()
    
    def _ensure_default_admin(self):
        """Create default admin user if no users exist"""
        if not self.users:
            self.create_user(UserCreate(
                username="admin",
                password="admin123",
                role="admin"
            ))
            logger.info("Created default admin user (username: admin, password: admin123)")
    
    def load_users(self):
        """Load users from file"""
        try:
            if os.path.exists(USERS_FILE):
                with open(USERS_FILE, 'r') as f:
                    self.users = json.load(f)
                logger.info(f"Loaded {len(self.users)} users")
        except Exception as e:
            logger.error(f"Error loading users: {e}")
            self.users = {}
    
    def save_users(self):
        """Save users to file"""
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving users: {e}")
    
    def create_user(self, user: UserCreate) -> Optional[UserResponse]:
        """Create a new user"""
        if user.username in self.users:
            return None  # User already exists
        
        user_id = secrets.token_hex(8)
        now = datetime.now(timezone.utc).isoformat()
        
        self.users[user.username] = {
            "id": user_id,
            "username": user.username,
            "password_hash": hash_password(user.password),
            "role": user.role,
            "created_at": now,
            "last_login": None,
            "is_active": True
        }
        
        self.save_users()
        logger.info(f"Created user: {user.username}")
        
        return UserResponse(
            id=user_id,
            username=user.username,
            role=user.role,
            created_at=now,
            is_active=True
        )
    
    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user and return user data if valid"""
        user = self.users.get(username)
        if not user:
            return None
        
        if not user.get("is_active", True):
            return None
        
        if not verify_password(password, user.get("password_hash", "")):
            return None
        
        # Update last login
        user["last_login"] = datetime.now(timezone.utc).isoformat()
        self.save_users()
        
        return user
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        return self.users.get(username)
    
    def get_all_users(self) -> List[UserResponse]:
        """Get all users (without password hashes)"""
        return [
            UserResponse(
                id=u["id"],
                username=u["username"],
                role=u["role"],
                created_at=u["created_at"],
                last_login=u.get("last_login"),
                is_active=u.get("is_active", True)
            )
            for u in self.users.values()
        ]
    
    def update_user(self, username: str, updates: Dict) -> bool:
        """Update user data"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        
        if "password" in updates:
            user["password_hash"] = hash_password(updates["password"])
        if "role" in updates:
            user["role"] = updates["role"]
        if "is_active" in updates:
            user["is_active"] = updates["is_active"]
        
        self.save_users()
        return True
    
    def delete_user(self, username: str) -> bool:
        """Delete user"""
        if username not in self.users:
            return False
        
        del self.users[username]
        self.save_users()
        return True


# Create global user store instance
user_store = UserStore()


# --- FastAPI Dependencies ---

security = HTTPBearer(auto_error=False)


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict:
    """
    Dependency to get current authenticated user.
    Returns user dict if authenticated, raises HTTPException otherwise.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = user_store.get_user(payload["sub"])
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return {
        "username": user["username"],
        "role": user["role"],
        "id": user["id"]
    }


async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[Dict]:
    """
    Dependency to get current user if authenticated, None otherwise.
    Does not raise exception if not authenticated.
    """
    if credentials is None:
        return None
    
    payload = verify_token(credentials.credentials)
    if payload is None:
        return None
    
    user = user_store.get_user(payload["sub"])
    if user is None:
        return None
    
    return {
        "username": user["username"],
        "role": user["role"],
        "id": user["id"]
    }


def require_role(required_roles: List[str]):
    """
    Dependency factory to require specific roles.
    Usage: @app.get("/admin", dependencies=[Depends(require_role(["admin"]))])
    """
    async def role_checker(current_user: Dict = Depends(get_current_user)):
        if current_user["role"] not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {required_roles}"
            )
        return current_user
    return role_checker


# --- Auth Functions ---

def login_user(username: str, password: str) -> Optional[TokenResponse]:
    """
    Authenticate user and return token response.
    Returns None if authentication fails.
    """
    user = user_store.authenticate(username, password)
    if user is None:
        return None
    
    token, exp_timestamp = create_token(username, user["role"])
    now = int(datetime.now(timezone.utc).timestamp())
    
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=exp_timestamp - now,
        user=UserResponse(
            id=user["id"],
            username=user["username"],
            role=user["role"],
            created_at=user["created_at"],
            last_login=user.get("last_login"),
            is_active=user.get("is_active", True)
        )
    )
