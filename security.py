#!/usr/bin/env python3
"""
Security Modules for Nigerian Road Risk Reporter
Data encryption, RBAC, CAPTCHA, and secure key management
"""

import streamlit as st
import sqlite3
import hashlib
import base64
import os
import json
import random
import string
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Security configuration
SECURITY_CONFIG = {
    'encryption_enabled': True,
    'captcha_enabled': True,
    'session_timeout_minutes': 30,
    'max_login_attempts': 3,
    'password_min_length': 8,
    'require_special_chars': True
}

class SecurityManager:
    """Main security manager class"""
    
    def __init__(self):
        self.fernet = None
        self.initialize_encryption()
    
    def initialize_encryption(self):
        """Initialize encryption with Fernet key"""
        try:
            # Try to load existing key from environment or file
            key = self._load_encryption_key()
            if key:
                self.fernet = Fernet(key)
            else:
                # Generate new key
                key = Fernet.generate_key()
                self.fernet = Fernet(key)
                self._save_encryption_key(key)
                
        except Exception as e:
            st.error(f"Encryption initialization failed: {str(e)}")
            self.fernet = None
    
    def _load_encryption_key(self) -> Optional[bytes]:
        """Load encryption key from environment or file"""
        try:
            # Try environment variable first
            key = os.getenv('ENCRYPTION_KEY')
            if key:
                return base64.urlsafe_b64decode(key)
            
            # Try loading from .env file
            if os.path.exists('.env'):
                with open('.env', 'r') as f:
                    for line in f:
                        if line.startswith('ENCRYPTION_KEY='):
                            key = line.split('=', 1)[1].strip()
                            return base64.urlsafe_b64decode(key)
            
            return None
            
        except Exception:
            return None
    
    def _save_encryption_key(self, key: bytes):
        """Save encryption key to .env file"""
        try:
            key_b64 = base64.urlsafe_b64encode(key).decode()
            
            # Create or update .env file
            env_content = f"ENCRYPTION_KEY={key_b64}\n"
            
            with open('.env', 'w') as f:
                f.write(env_content)
            
            # Set environment variable
            os.environ['ENCRYPTION_KEY'] = key_b64
            
        except Exception as e:
            st.error(f"Failed to save encryption key: {str(e)}")
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.fernet or not SECURITY_CONFIG['encryption_enabled']:
            return data
        
        try:
            encrypted_data = self.fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")
            return data
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.fernet or not SECURITY_CONFIG['encryption_enabled']:
            return encrypted_data
        
        try:
            # Check if data is actually encrypted
            if not encrypted_data or len(encrypted_data) < 50:
                return encrypted_data
            
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception:
            # If decryption fails, return original data
            return encrypted_data
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA256 with salt"""
        salt = os.urandom(16).hex()
        hash_obj = hashlib.sha256()
        hash_obj.update((password + salt).encode())
        return f"{salt}${hash_obj.hexdigest()}"
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_value = hashed.split('$', 1)
            hash_obj = hashlib.sha256()
            hash_obj.update((password + salt).encode())
            return hash_obj.hexdigest() == hash_value
        except Exception:
            return False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < SECURITY_CONFIG['password_min_length']:
            return False, f"Password must be at least {SECURITY_CONFIG['password_min_length']} characters"
        
        if SECURITY_CONFIG['require_special_chars']:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(char in special_chars for char in password):
                return False, "Password must contain at least one special character"
        
        if not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(char.isdigit() for char in password):
            return False, "Password must contain at least one number"
        
        return True, "Password is strong"

class CAPTCHAGenerator:
    """CAPTCHA generation and validation"""
    
    @staticmethod
    def generate_math_captcha() -> Tuple[str, int]:
        """Generate a simple math CAPTCHA"""
        num1 = random.randint(1, 20)
        num2 = random.randint(1, 20)
        operation = random.choice(['+', '-', '*'])
        
        if operation == '+':
            answer = num1 + num2
            question = f"{num1} + {num2} = ?"
        elif operation == '-':
            answer = num1 - num2
            question = f"{num1} - {num2} = ?"
        else:
            answer = num1 * num2
            question = f"{num1} × {num2} = ?"
        
        return question, answer
    
    @staticmethod
    def generate_text_captcha() -> Tuple[str, str]:
        """Generate a text-based CAPTCHA"""
        # Simple word-based CAPTCHA
        words = ['ROAD', 'SAFETY', 'TRAFFIC', 'DRIVE', 'CAR', 'STOP', 'GO', 'SLOW']
        word = random.choice(words)
        
        # Add some noise
        captcha_text = ''.join(random.choice([c, c.lower()]) for c in word)
        return captcha_text, word

class RBACManager:
    """Role-Based Access Control Manager"""
    
    ROLES = {
        'admin': {
            'permissions': ['read', 'write', 'delete', 'moderate', 'manage_users', 'view_analytics'],
            'description': 'Full system access'
        },
        'driver': {
            'permissions': ['read', 'write', 'view_own_reports'],
            'description': 'Can submit and view own reports'
        },
        'public': {
            'permissions': ['read', 'write'],
            'description': 'Can submit reports and view public data'
        }
    }
    
    @staticmethod
    def check_permission(user_role: str, required_permission: str) -> bool:
        """Check if user has required permission"""
        if user_role not in RBACManager.ROLES:
            return False
        
        user_permissions = RBACManager.ROLES[user_role]['permissions']
        return required_permission in user_permissions
    
    @staticmethod
    def get_user_permissions(user_role: str) -> list:
        """Get list of user permissions"""
        return RBACManager.ROLES.get(user_role, {}).get('permissions', [])
    
    @staticmethod
    def require_permission(permission: str):
        """Decorator to require specific permission"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                if 'user_role' not in st.session_state:
                    st.error("Access denied. Please log in.")
                    return
                
                if not RBACManager.check_permission(st.session_state.user_role, permission):
                    st.error(f"Access denied. Requires '{permission}' permission.")
                    return
                
                return func(*args, **kwargs)
            return wrapper
        return decorator

class SessionManager:
    """Session management and security"""
    
    @staticmethod
    def create_session(user_data: dict):
        """Create secure user session"""
        session_data = {
            'user_id': user_data['id'],
            'username': user_data['full_name'],
            'email': user_data.get('email', ''),
            'role': user_data['role'],
            'login_time': datetime.now().isoformat(),
            'session_id': SessionManager._generate_session_id()
        }
        
        st.session_state.update(session_data)
        st.session_state.logged_in = True
    
    @staticmethod
    def _generate_session_id() -> str:
        """Generate unique session ID"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    @staticmethod
    def validate_session() -> bool:
        """Validate current session"""
        if not st.session_state.get('logged_in'):
            return False
        
        # Check session timeout
        login_time = datetime.fromisoformat(st.session_state.get('login_time', '1970-01-01T00:00:00'))
        timeout_minutes = SECURITY_CONFIG['session_timeout_minutes']
        
        if datetime.now() - login_time > timedelta(minutes=timeout_minutes):
            SessionManager.clear_session()
            return False
        
        return True
    
    @staticmethod
    def clear_session():
        """Clear user session"""
        session_keys = ['logged_in', 'user_id', 'username', 'email', 'role', 'login_time', 'session_id']
        for key in session_keys:
            if key in st.session_state:
                del st.session_state[key]

def initialize_security_database():
    """Initialize security-related database tables"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Create security logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        # Create login attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                ip_address TEXT,
                success BOOLEAN DEFAULT FALSE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create CAPTCHA sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS captcha_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                captcha_answer TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        st.error(f"Error initializing security database: {str(e)}")

def log_security_event(user_id: int, action: str, details: str = None):
    """Log security events"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_logs (user_id, action, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, action, "127.0.0.1", "Streamlit App", details))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        st.error(f"Error logging security event: {str(e)}")

def check_login_attempts(identifier: str) -> bool:
    """Check if user has exceeded login attempts"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Count recent failed attempts
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts 
            WHERE identifier = ? AND success = FALSE 
            AND timestamp > datetime('now', '-15 minutes')
        ''', (identifier,))
        
        failed_attempts = cursor.fetchone()[0]
        conn.close()
        
        return failed_attempts < SECURITY_CONFIG['max_login_attempts']
        
    except Exception:
        return True

def log_login_attempt(identifier: str, success: bool):
    """Log login attempt"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO login_attempts (identifier, ip_address, success)
            VALUES (?, ?, ?)
        ''', (identifier, "127.0.0.1", success))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        st.error(f"Error logging login attempt: {str(e)}")

def display_captcha() -> bool:
    """Display CAPTCHA and return validation result"""
    if not SECURITY_CONFIG['captcha_enabled']:
        return True
    
    st.markdown("### 🤖 Security Verification")
    
    # Generate CAPTCHA
    captcha_type = random.choice(['math', 'text'])
    
    if captcha_type == 'math':
        question, answer = CAPTCHAGenerator.generate_math_captcha()
        st.markdown(f"**Solve this math problem:** {question}")
    else:
        captcha_text, correct_answer = CAPTCHAGenerator.generate_text_captcha()
        st.markdown(f"**Enter this text exactly:** `{captcha_text}`")
        answer = correct_answer
    
    # User input
    user_answer = st.text_input("Your answer:", key="captcha_answer")
    
    if st.button("Verify", key="verify_captcha"):
        if user_answer and user_answer.strip().upper() == str(answer).upper():
            st.success("✅ CAPTCHA verified successfully!")
            return True
        else:
            st.error("❌ Incorrect answer. Please try again.")
            st.rerun()
    
    return False

def display_security_settings():
    """Display security settings interface"""
    st.markdown("## 🔐 Security Settings")
    
    # Security configuration
    with st.expander("Security Configuration", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            SECURITY_CONFIG['encryption_enabled'] = st.checkbox(
                "Enable Data Encryption",
                value=SECURITY_CONFIG['encryption_enabled'],
                key="encryption_enabled"
            )
            
            SECURITY_CONFIG['captcha_enabled'] = st.checkbox(
                "Enable CAPTCHA",
                value=SECURITY_CONFIG['captcha_enabled'],
                key="captcha_enabled"
            )
        
        with col2:
            SECURITY_CONFIG['session_timeout_minutes'] = st.number_input(
                "Session Timeout (minutes)",
                min_value=5,
                max_value=120,
                value=SECURITY_CONFIG['session_timeout_minutes'],
                key="session_timeout"
            )
            
            SECURITY_CONFIG['max_login_attempts'] = st.number_input(
                "Max Login Attempts",
                min_value=1,
                max_value=10,
                value=SECURITY_CONFIG['max_login_attempts'],
                key="max_attempts"
            )
    
    # Security logs
    with st.expander("Security Logs", expanded=False):
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT action, timestamp, details 
                FROM security_logs 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''')
            
            logs = cursor.fetchall()
            conn.close()
            
            if logs:
                for log in logs:
                    st.write(f"**{log[0]}** - {log[1]} - {log[2]}")
            else:
                st.info("No security logs found")
                
        except Exception as e:
            st.error(f"Error loading security logs: {str(e)}")

def main():
    """Main function for Security Modules"""
    st.set_page_config(
        page_title="Security Modules",
        page_icon="🔐",
        layout="wide"
    )
    
    st.markdown("# 🔐 Security Modules")
    st.markdown("Data encryption, RBAC, CAPTCHA, and secure key management")
    
    # Initialize security
    initialize_security_database()
    security_manager = SecurityManager()
    
    # Display security settings
    display_security_settings()
    
    # Test encryption
    with st.expander("Encryption Test", expanded=False):
        test_data = st.text_input("Enter text to encrypt:", key="encrypt_test")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Encrypt", key="encrypt_btn"):
                if test_data:
                    encrypted = security_manager.encrypt_data(test_data)
                    st.text_area("Encrypted:", encrypted, height=100)
        
        with col2:
            encrypted_input = st.text_input("Enter encrypted text to decrypt:", key="decrypt_test")
            if st.button("Decrypt", key="decrypt_btn"):
                if encrypted_input:
                    decrypted = security_manager.decrypt_data(encrypted_input)
                    st.text_area("Decrypted:", decrypted, height=100)
    
    # Test CAPTCHA
    with st.expander("CAPTCHA Test", expanded=False):
        if display_captcha():
            st.success("CAPTCHA validation successful!")
    
    # Password strength checker
    with st.expander("Password Strength Checker", expanded=False):
        password = st.text_input("Enter password to check:", type="password", key="password_check")
        
        if password:
            is_strong, message = security_manager.validate_password_strength(password)
            if is_strong:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ {message}")

if __name__ == "__main__":
    main() 