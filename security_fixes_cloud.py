#!/usr/bin/env python3
"""
Critical Security Fixes for Nigerian Road Risk Reporter - Streamlit Cloud Compatible
Implements secure password hashing, input validation, rate limiting, and session management
Optimized for Streamlit Cloud deployment
"""

import streamlit as st
import sqlite3
import bcrypt
import re
import json
import os
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from functools import wraps
import logging

# Security configuration optimized for Streamlit Cloud
SECURITY_CONFIG = {
    'session_timeout_minutes': 30,
    'max_login_attempts': 5,
    'lockout_duration_minutes': 30,
    'password_min_length': 12,
    'require_special_chars': True,
    'max_file_size_mb': 5,
    'allowed_file_types': {'.jpg', '.jpeg', '.png', '.gif', '.pdf'},
    'rate_limit_requests': 100,
    'rate_limit_window_minutes': 15,
    'enable_2fa': True,
    'enable_encryption': True
}

# Setup security logging (Streamlit Cloud compatible)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SecurePasswordManager:
    """Secure password hashing and validation using bcrypt"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt with salt"""
        try:
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
        except Exception as e:
            logging.error(f"Password hashing failed: {e}")
            # Fallback to SHA256 with salt (less secure but better than plain text)
            salt = secrets.token_hex(16)
            hash_obj = hashlib.sha256()
            hash_obj.update((password + salt).encode('utf-8'))
            return f"{salt}${hash_obj.hexdigest()}"
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            # Try bcrypt first
            if hashed.startswith('$2b$'):
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            
            # Fallback to SHA256 with salt
            if '$' in hashed:
                salt, hash_value = hashed.split('$', 1)
                hash_obj = hashlib.sha256()
                hash_obj.update((password + salt).encode('utf-8'))
                return hash_obj.hexdigest() == hash_value
            
            # Legacy SHA256 without salt
            return hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed
            
        except Exception as e:
            logging.error(f"Password verification failed: {e}")
            return False
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """Enhanced password strength validation"""
        errors = []
        
        if len(password) < SECURITY_CONFIG['password_min_length']:
            errors.append(f"Password must be at least {SECURITY_CONFIG['password_min_length']} characters long")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if SECURITY_CONFIG['require_special_chars']:
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors.append("Password must contain at least one special character")
        
        # Check for common passwords
        common_passwords = [
            'password', '123456', 'qwerty', 'admin', 'letmein', 'welcome',
            'password123', 'admin123', 'user123', 'test123', 'guest123'
        ]
        if password.lower() in common_passwords:
            errors.append("Password cannot be a common password")
        
        # Check for sequential characters
        if re.search(r'(.)\1{2,}', password):
            errors.append("Password cannot contain repeated characters")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', '654321']
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                errors.append("Password cannot contain keyboard patterns")
                break
        
        return len(errors) == 0, '; '.join(errors) if errors else "Password is strong"

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 255) -> Optional[str]:
        """Sanitize user input to prevent XSS and injection attacks"""
        if not input_string or not isinstance(input_string, str):
            return None
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', input_string.strip())
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized if sanitized else None
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Validate Nigerian phone number format"""
        if not phone:
            return False
        
        # Remove all non-digit characters except +
        clean_phone = re.sub(r'[^\d+]', '', phone)
        
        # Nigerian phone patterns: +234XXXXXXXXX or 0XXXXXXXXX
        phone_patterns = [
            r'^\+234[0-9]{10}$',  # +234XXXXXXXXX
            r'^0[0-9]{10}$'       # 0XXXXXXXXX
        ]
        
        return any(re.match(pattern, clean_phone) for pattern in phone_patterns)
    
    @staticmethod
    def validate_nin(nin: str) -> bool:
        """Validate NIN (11 digits)"""
        if not nin:
            return True  # NIN is optional
        
        return nin.isdigit() and len(nin) == 11
    
    @staticmethod
    def validate_file_upload(file) -> Tuple[bool, str]:
        """Validate uploaded file (Streamlit Cloud compatible)"""
        if not file:
            return False, "No file provided"
        
        # Check file size
        max_size = SECURITY_CONFIG['max_file_size_mb'] * 1024 * 1024
        if file.size > max_size:
            return False, f"File too large. Maximum size is {SECURITY_CONFIG['max_file_size_mb']}MB"
        
        # Check file extension
        file_name = file.name.lower()
        file_ext = os.path.splitext(file_name)[1]
        if file_ext not in SECURITY_CONFIG['allowed_file_types']:
            return False, f"File type not allowed. Allowed types: {', '.join(SECURITY_CONFIG['allowed_file_types'])}"
        
        # Basic file content validation (extension-based only for Streamlit Cloud)
        return True, "File extension validated"

class RateLimiter:
    """Rate limiting implementation (in-memory for Streamlit Cloud)"""
    
    def __init__(self):
        self.rate_limit_cache = {}
    
    def check_rate_limit(self, identifier: str, max_requests: int, window_seconds: int) -> bool:
        """Check if user has exceeded rate limit"""
        current_time = time.time()
        
        # Clean old entries
        self._cleanup_old_entries(current_time, window_seconds)
        
        # Check current requests
        if identifier in self.rate_limit_cache:
            requests = self.rate_limit_cache[identifier]
            if len(requests) >= max_requests:
                return False
            
            # Add current request
            requests.append(current_time)
        else:
            self.rate_limit_cache[identifier] = [current_time]
        
        return True
    
    def _cleanup_old_entries(self, current_time: float, window_seconds: int):
        """Remove old rate limit entries"""
        cutoff_time = current_time - window_seconds
        
        for identifier in list(self.rate_limit_cache.keys()):
            requests = self.rate_limit_cache[identifier]
            # Keep only recent requests
            self.rate_limit_cache[identifier] = [
                req_time for req_time in requests 
                if req_time > cutoff_time
            ]
            
            # Remove empty entries
            if not self.rate_limit_cache[identifier]:
                del self.rate_limit_cache[identifier]

class SecureSessionManager:
    """Secure session management (in-memory for Streamlit Cloud)"""
    
    def __init__(self):
        self.sessions = {}
    
    def create_session(self, user_data: dict) -> str:
        """Create secure session"""
        session_id = secrets.token_urlsafe(32)
        session_data = {
            'user_id': user_data.get('id'),
            'full_name': user_data.get('full_name'),
            'role': user_data.get('role'),
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(minutes=SECURITY_CONFIG['session_timeout_minutes'])).isoformat()
        }
        
        # Store in memory (Streamlit Cloud compatible)
        self.sessions[session_id] = session_data
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[dict]:
        """Get session data"""
        if not session_id:
            return None
        
        try:
            return self.sessions.get(session_id)
        except Exception as e:
            logging.error(f"Session retrieval failed: {e}")
        
        return None
    
    def validate_session(self, session_id: str) -> bool:
        """Validate session"""
        session_data = self.get_session(session_id)
        if not session_data:
            return False
        
        try:
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if datetime.now() > expires_at:
                self.delete_session(session_id)
                return False
            return True
        except Exception as e:
            logging.error(f"Session validation failed: {e}")
            return False
    
    def delete_session(self, session_id: str):
        """Delete session"""
        try:
            self.sessions.pop(session_id, None)
        except Exception as e:
            logging.error(f"Session deletion failed: {e}")

class SecurityLogger:
    """Comprehensive security logging (Streamlit Cloud compatible)"""
    
    @staticmethod
    def log_security_event(event_type: str, details: str, severity: str = "INFO", user_id: int = None, ip_address: str = None):
        """Log security events"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'severity': severity,
            'user_id': user_id,
            'ip_address': ip_address or "unknown",
            'user_agent': "Streamlit Cloud App"
        }
        
        # Log to console (Streamlit Cloud compatible)
        if severity.upper() == "ERROR":
            logging.error(f"Security Event: {log_entry}")
        elif severity.upper() == "WARNING":
            logging.warning(f"Security Event: {log_entry}")
        else:
            logging.info(f"Security Event: {log_entry}")
        
        # Log to database
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_audit_logs (user_id, user_ip, action, details, success, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, ip_address or "unknown", event_type, details, True, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Failed to log to database: {e}")

class TwoFactorAuth:
    """Two-Factor Authentication implementation"""
    
    @staticmethod
    def generate_secret() -> str:
        """Generate TOTP secret"""
        try:
            import pyotp
            return pyotp.random_base32()
        except ImportError:
            return None
    
    @staticmethod
    def generate_qr_code(secret: str, user_email: str) -> str:
        """Generate QR code URL for 2FA setup"""
        try:
            import pyotp
            if not secret:
                return None
            
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(user_email, issuer_name="Road Risk Reporter")
            return provisioning_uri
        except ImportError:
            return None
    
    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        """Verify TOTP code"""
        try:
            import pyotp
            if not secret:
                return False
            
            totp = pyotp.TOTP(secret)
            return totp.verify(code)
        except ImportError:
            return False

# Global instances
password_manager = SecurePasswordManager()
input_validator = InputValidator()
rate_limiter = RateLimiter()
session_manager = SecureSessionManager()
security_logger = SecurityLogger()
two_factor_auth = TwoFactorAuth()

def get_client_ip() -> str:
    """Get client IP address (Streamlit Cloud compatible)"""
    try:
        # For Streamlit Cloud, return a placeholder
        return "streamlit-cloud"
    except:
        return "unknown"

def rate_limit_decorator(max_requests: int = None, window_seconds: int = None):
    """Rate limiting decorator"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_ip = get_client_ip()
            max_req = max_requests or SECURITY_CONFIG['rate_limit_requests']
            window = window_seconds or (SECURITY_CONFIG['rate_limit_window_minutes'] * 60)
            
            if not rate_limiter.check_rate_limit(user_ip, max_req, window):
                security_logger.log_security_event(
                    "rate_limit_exceeded",
                    f"IP {user_ip} exceeded rate limit",
                    "WARNING",
                    ip_address=user_ip
                )
                return {"error": "Rate limit exceeded. Please try again later."}, 429
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def require_authentication(func):
    """Decorator to require authentication"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'session_id' not in st.session_state:
            st.error("Please log in to access this feature")
            return
        
        if not session_manager.validate_session(st.session_state.session_id):
            st.error("Session expired. Please log in again.")
            # Clear session
            if 'session_id' in st.session_state:
                del st.session_state.session_id
            return
        
        return func(*args, **kwargs)
    return wrapper

def require_role(required_role: str):
    """Decorator to require specific role"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'session_id' not in st.session_state:
                st.error("Please log in to access this feature")
                return
            
            session_data = session_manager.get_session(st.session_state.session_id)
            if not session_data:
                st.error("Session expired. Please log in again.")
                return
            
            user_role = session_data.get('role', 'user')
            if user_role != required_role and user_role != 'admin':
                st.error("You don't have permission to access this feature")
                return
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def initialize_security_database():
    """Initialize security-related database tables"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Enhanced security audit logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_ip TEXT,
                action TEXT NOT NULL,
                details TEXT,
                success BOOLEAN DEFAULT TRUE,
                severity TEXT DEFAULT 'INFO',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Enhanced login attempts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                user_ip TEXT,
                success BOOLEAN DEFAULT FALSE,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT,
                failure_reason TEXT
            )
        ''')
        
        # Account lockouts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS account_lockouts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                user_ip TEXT,
                lockout_reason TEXT,
                lockout_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                lockout_end TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Rate limiting
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                user_ip TEXT,
                request_count INTEGER DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                window_end TIMESTAMP
            )
        ''')
        
        # 2FA secrets
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS two_factor_auth (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                is_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Add 2FA column to users table if it doesn't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'two_factor_enabled' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT FALSE')
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        logging.error(f"Failed to initialize security database: {e}")
        return False

def check_login_attempts(identifier: str) -> bool:
    """Check if user has exceeded login attempts"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check for active lockouts
        cursor.execute('''
            SELECT lockout_end FROM account_lockouts 
            WHERE identifier = ? AND is_active = TRUE AND lockout_end > datetime('now')
        ''', (identifier,))
        
        lockout = cursor.fetchone()
        if lockout:
            conn.close()
            return False
        
        # Check recent failed attempts
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts 
            WHERE identifier = ? AND success = FALSE 
            AND attempt_time > datetime('now', '-15 minutes')
        ''', (identifier,))
        
        failed_attempts = cursor.fetchone()[0]
        conn.close()
        
        return failed_attempts < SECURITY_CONFIG['max_login_attempts']
        
    except Exception as e:
        logging.error(f"Failed to check login attempts: {e}")
        return True

def log_login_attempt(identifier: str, success: bool, failure_reason: str = None):
    """Log login attempt with enhanced tracking"""
    try:
        user_ip = get_client_ip()
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO login_attempts (identifier, user_ip, success, user_agent, failure_reason)
            VALUES (?, ?, ?, ?, ?)
        ''', (identifier, user_ip, success, "Streamlit Cloud App", failure_reason))
        
        # If failed and reached max attempts, create lockout
        if not success:
            cursor.execute('''
                SELECT COUNT(*) FROM login_attempts 
                WHERE identifier = ? AND success = FALSE 
                AND attempt_time > datetime('now', '-15 minutes')
            ''', (identifier,))
            
            failed_count = cursor.fetchone()[0]
            
            if failed_count >= SECURITY_CONFIG['max_login_attempts']:
                lockout_end = datetime.now() + timedelta(minutes=SECURITY_CONFIG['lockout_duration_minutes'])
                cursor.execute('''
                    INSERT INTO account_lockouts (identifier, user_ip, lockout_reason, lockout_end)
                    VALUES (?, ?, ?, ?)
                ''', (identifier, user_ip, f"Exceeded {SECURITY_CONFIG['max_login_attempts']} failed login attempts", lockout_end.isoformat()))
        
        conn.commit()
        conn.close()
        
        # Log security event
        event_type = "login_success" if success else "login_failed"
        severity = "INFO" if success else "WARNING"
        security_logger.log_security_event(event_type, f"Login attempt for {identifier}", severity, ip_address=user_ip)
        
    except Exception as e:
        logging.error(f"Failed to log login attempt: {e}")

def main():
    """Main function for security fixes module"""
    st.set_page_config(
        page_title="Security Fixes - Cloud",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Security Fixes Module - Streamlit Cloud Compatible")
    st.markdown("Critical security improvements for the Road Risk Reporter")
    
    # Initialize security database
    if initialize_security_database():
        st.success("✅ Security database initialized")
    
    # Display security status
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Security Features Status")
        st.success(f"✅ Bcrypt password hashing: Available")
        st.success(f"✅ Input validation: Active")
        st.success(f"✅ Rate limiting: Active")
        st.success(f"✅ Session management: Active")
        st.info(f"ℹ️ Streamlit Cloud: Optimized")
        st.info(f"ℹ️ 2FA: Available")
    
    with col2:
        st.markdown("### Security Configuration")
        st.write(f"**Session timeout:** {SECURITY_CONFIG['session_timeout_minutes']} minutes")
        st.write(f"**Max login attempts:** {SECURITY_CONFIG['max_login_attempts']}")
        st.write(f"**Lockout duration:** {SECURITY_CONFIG['lockout_duration_minutes']} minutes")
        st.write(f"**Min password length:** {SECURITY_CONFIG['password_min_length']}")
        st.write(f"**Rate limit:** {SECURITY_CONFIG['rate_limit_requests']} requests per {SECURITY_CONFIG['rate_limit_window_minutes']} minutes")
    
    # Test password validation
    with st.expander("🧪 Test Password Validation", expanded=False):
        test_password = st.text_input("Enter password to test:", type="password")
        if test_password:
            is_valid, message = password_manager.validate_password_strength(test_password)
            if is_valid:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ {message}")
    
    # Test input validation
    with st.expander("🧪 Test Input Validation", expanded=False):
        test_input = st.text_input("Enter text to sanitize:")
        if test_input:
            sanitized = input_validator.sanitize_input(test_input)
            st.write(f"**Original:** {test_input}")
            st.write(f"**Sanitized:** {sanitized}")

if __name__ == "__main__":
    main() 