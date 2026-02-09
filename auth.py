"""
Authentication System - Email signup/login, API key generation
"""
import os
import json
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from dataclasses import dataclass, field, asdict

from dotenv import load_dotenv
load_dotenv()


@dataclass
class User:
    """User account"""
    id: str
    email: str
    password_hash: str
    name: str = ""
    company: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    verified: bool = False
    api_keys: List[str] = field(default_factory=list)
    plan: str = "free"  # free, pro, enterprise
    usage: Dict = field(default_factory=lambda: {"scans": 0, "api_calls": 0})


@dataclass
class APIKey:
    """API Key for product access"""
    key: str
    user_id: str
    name: str
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_used: Optional[str] = None
    active: bool = True
    permissions: List[str] = field(default_factory=lambda: ["read", "scan"])
    rate_limit: int = 100  # requests per hour


class AuthSystem:
    """
    Complete authentication system for VibeSecurity.

    Features:
    - Email signup/login
    - Password hashing with salt
    - API key generation & management
    - Usage tracking
    - Plan management
    """

    def __init__(self, data_file: str = "users.json"):
        self.data_file = data_file
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, APIKey] = {}
        self.sessions: Dict[str, Dict] = {}  # session_token -> user_id
        self._load_data()

    def _load_data(self):
        """Load user data from file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    for uid, udata in data.get("users", {}).items():
                        self.users[uid] = User(**udata)
                    for kid, kdata in data.get("api_keys", {}).items():
                        self.api_keys[kid] = APIKey(**kdata)
            except:
                pass

    def _save_data(self):
        """Save user data to file"""
        data = {
            "users": {uid: asdict(u) for uid, u in self.users.items()},
            "api_keys": {kid: asdict(k) for kid, k in self.api_keys.items()}
        }
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            100000
        ).hex()
        return f"{salt}:{hashed}", salt

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, _ = stored_hash.split(':')
            new_hash, _ = self._hash_password(password, salt)
            return new_hash == stored_hash
        except:
            return False

    def signup(self, email: str, password: str, name: str = "", company: str = "") -> Dict:
        """Register a new user"""
        # Check if email exists
        for user in self.users.values():
            if user.email.lower() == email.lower():
                return {"success": False, "error": "Email already registered"}

        # Validate email
        if not email or "@" not in email:
            return {"success": False, "error": "Invalid email address"}

        # Validate password
        if len(password) < 8:
            return {"success": False, "error": "Password must be at least 8 characters"}

        # Create user
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        password_hash, _ = self._hash_password(password)

        user = User(
            id=user_id,
            email=email.lower(),
            password_hash=password_hash,
            name=name,
            company=company
        )

        self.users[user_id] = user
        self._save_data()

        # Generate initial API key
        api_key = self.generate_api_key(user_id, "Default Key")

        return {
            "success": True,
            "user_id": user_id,
            "email": email,
            "api_key": api_key["key"],
            "message": "Account created successfully"
        }

    def login(self, email: str, password: str) -> Dict:
        """Authenticate user"""
        # Find user by email
        user = None
        for u in self.users.values():
            if u.email.lower() == email.lower():
                user = u
                break

        if not user:
            return {"success": False, "error": "Invalid email or password"}

        if not self._verify_password(password, user.password_hash):
            return {"success": False, "error": "Invalid email or password"}

        # Create session token
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            "user_id": user.id,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=7)).isoformat()
        }

        return {
            "success": True,
            "user_id": user.id,
            "email": user.email,
            "name": user.name,
            "session_token": session_token,
            "plan": user.plan
        }

    def logout(self, session_token: str) -> bool:
        """End user session"""
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False

    def get_user_from_session(self, session_token: str) -> Optional[User]:
        """Get user from session token"""
        session = self.sessions.get(session_token)
        if not session:
            return None

        # Check expiry
        if datetime.fromisoformat(session["expires_at"]) < datetime.now():
            del self.sessions[session_token]
            return None

        return self.users.get(session["user_id"])

    def generate_api_key(self, user_id: str, name: str = "API Key") -> Dict:
        """Generate a new API key for user"""
        if user_id not in self.users:
            return {"success": False, "error": "User not found"}

        # Generate key: vs_live_xxxxxxxxxxxx
        key = f"vs_live_{secrets.token_urlsafe(24)}"

        api_key = APIKey(
            key=key,
            user_id=user_id,
            name=name
        )

        self.api_keys[key] = api_key
        self.users[user_id].api_keys.append(key)
        self._save_data()

        return {
            "success": True,
            "key": key,
            "name": name,
            "message": "API key generated successfully. Store it securely - you won't see it again."
        }

    def validate_api_key(self, key: str) -> Optional[Dict]:
        """Validate API key and return user info"""
        api_key = self.api_keys.get(key)
        if not api_key or not api_key.active:
            return None

        # Update last used
        api_key.last_used = datetime.now().isoformat()

        user = self.users.get(api_key.user_id)
        if not user:
            return None

        # Increment usage
        user.usage["api_calls"] = user.usage.get("api_calls", 0) + 1
        self._save_data()

        return {
            "user_id": user.id,
            "email": user.email,
            "plan": user.plan,
            "permissions": api_key.permissions
        }

    def revoke_api_key(self, user_id: str, key: str) -> bool:
        """Revoke an API key"""
        api_key = self.api_keys.get(key)
        if not api_key or api_key.user_id != user_id:
            return False

        api_key.active = False
        self._save_data()
        return True

    def get_user_api_keys(self, user_id: str) -> List[Dict]:
        """Get all API keys for a user"""
        keys = []
        for key, api_key in self.api_keys.items():
            if api_key.user_id == user_id:
                keys.append({
                    "key": f"{key[:12]}...{key[-4:]}",  # Masked
                    "name": api_key.name,
                    "created_at": api_key.created_at,
                    "last_used": api_key.last_used,
                    "active": api_key.active
                })
        return keys

    def get_stats(self) -> Dict:
        """Get system statistics"""
        total_users = len(self.users)
        active_keys = len([k for k in self.api_keys.values() if k.active])
        total_api_calls = sum(u.usage.get("api_calls", 0) for u in self.users.values())
        total_scans = sum(u.usage.get("scans", 0) for u in self.users.values())

        plans = {"free": 0, "pro": 0, "enterprise": 0}
        for user in self.users.values():
            plans[user.plan] = plans.get(user.plan, 0) + 1

        return {
            "total_users": total_users,
            "active_api_keys": active_keys,
            "total_api_calls": total_api_calls,
            "total_scans": total_scans,
            "users_by_plan": plans,
            "recent_signups": len([u for u in self.users.values()
                                   if datetime.fromisoformat(u.created_at) > datetime.now() - timedelta(days=7)])
        }

    def update_user_plan(self, user_id: str, plan: str) -> bool:
        """Update user's plan"""
        if user_id not in self.users:
            return False
        if plan not in ["free", "pro", "enterprise"]:
            return False

        self.users[user_id].plan = plan
        self._save_data()
        return True

    def increment_scan_usage(self, user_id: str) -> bool:
        """Increment scan count for user"""
        if user_id not in self.users:
            return False

        self.users[user_id].usage["scans"] = self.users[user_id].usage.get("scans", 0) + 1
        self._save_data()
        return True


# Global auth system instance
auth_system = AuthSystem()
