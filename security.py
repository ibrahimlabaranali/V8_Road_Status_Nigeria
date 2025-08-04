#!/usr/bin/env python3
"""
Security Modules for Nigerian Road Risk Reporter
Lightweight encryption, RBAC, CAPTCHA, and secure key management
Python 3.13 compatible - Streamlit Cloud ready
"""

import streamlit as st
import sqlite3
import hashlib
import base64
import os
import random
import string
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

# Try to import cryptography, fallback to simple encryption if not available
try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    st.warning("⚠️ Cryptography library not available. Using simple encryption fallback.")

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
        """Initialize encryption with Fernet key or fallback"""
        try:
            if CRYPTOGRAPHY_AVAILABLE:
                # Try to load existing key from environment or file
                key = self._load_encryption_key()
                if key:
                    self.fernet = Fernet(key)
                else:
                    # Generate new key
                    key = Fernet.generate_key()
                    self.fernet = Fernet(key)
                    self._save_encryption_key(key)
            else:
                st.info("Using simple encryption fallback (not recommended for production)")
                
        except Exception as e:
            st.error(f"Encryption initialization failed: {str(e)}")
            self.fernet = None
    
    def _load_encryption_key(self) -> Optional[bytes]:
        """Load encryption key from environment or file"""
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                return None
                
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
            if not CRYPTOGRAPHY_AVAILABLE:
                return
                
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
        if not SECURITY_CONFIG['encryption_enabled']:
            return data
        
        try:
            if CRYPTOGRAPHY_AVAILABLE and self.fernet:
                encrypted_data = self.fernet.encrypt(data.encode())
                return base64.urlsafe_b64encode(encrypted_data).decode()
            else:
                # Simple fallback encryption (not secure, just for compatibility)
                return base64.b64encode(data.encode()).decode()
                
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")
            return data
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not SECURITY_CONFIG['encryption_enabled']:
            return encrypted_data
        
        try:
            if CRYPTOGRAPHY_AVAILABLE and self.fernet:
                encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
                decrypted_data = self.fernet.decrypt(encrypted_bytes)
                return decrypted_data.decode()
            else:
                # Simple fallback decryption
                return base64.b64decode(encrypted_data.encode()).decode()
                
        except Exception as e:
            st.error(f"Decryption failed: {str(e)}")
            return encrypted_data
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA256"""
        try:
            return hashlib.sha256(password.encode('utf-8')).hexdigest()
        except Exception:
            return password  # Fallback
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            return hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed
        except Exception:
            return password == hashed  # Fallback
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < SECURITY_CONFIG['password_min_length']:
            return False, f"Password must be at least {SECURITY_CONFIG['password_min_length']} characters long"
        
        if SECURITY_CONFIG['require_special_chars']:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(char in special_chars for char in password):
                return False, "Password must contain at least one special character"
        
        return True, "Password is strong"

class CAPTCHAGenerator:
    """Simple CAPTCHA generator"""
    
    @staticmethod
    def generate_math_captcha() -> Tuple[str, int]:
        """Generate a simple math CAPTCHA"""
        try:
            num1 = random.randint(1, 10)
            num2 = random.randint(1, 10)
            operation = random.choice(['+', '-', '*'])
            
            if operation == '+':
                answer = num1 + num2
                question = f"{num1} + {num2} = ?"
            elif operation == '-':
                answer = num1 - num2
                question = f"{num1} - {num2} = ?"
            else:  # multiplication
                answer = num1 * num2
                question = f"{num1} × {num2} = ?"
            
            return question, answer
            
        except Exception:
            # Fallback
            return "2 + 3 = ?", 5
    
    @staticmethod
    def generate_text_captcha() -> Tuple[str, str]:
        """Generate a simple text CAPTCHA"""
        try:
            # Generate random 4-character string
            chars = string.ascii_uppercase + string.digits
            captcha_text = ''.join(random.choice(chars) for _ in range(4))
            return captcha_text, captcha_text
            
        except Exception:
            # Fallback
            return "ABC123", "ABC123"

class RBACManager:
    """Role-Based Access Control Manager"""
    
    ROLES = {
        'user': {
            'permissions': ['submit_report', 'view_reports', 'upvote_report'],
            'description': 'Regular user - can submit and view reports'
        },
        'moderator': {
            'permissions': ['submit_report', 'view_reports', 'upvote_report', 'moderate_reports', 'view_users'],
            'description': 'Moderator - can moderate reports and view users'
        },
        'admin': {
            'permissions': ['submit_report', 'view_reports', 'upvote_report', 'moderate_reports', 'view_users', 'manage_users', 'view_logs', 'system_config'],
            'description': 'Administrator - full system access'
        }
    }
    
    @staticmethod
    def check_permission(user_role: str, required_permission: str) -> bool:
        """Check if user has required permission"""
        try:
            if user_role not in RBACManager.ROLES:
                return False
            
            user_permissions = RBACManager.ROLES[user_role]['permissions']
            return required_permission in user_permissions
            
        except Exception:
            return False
    
    @staticmethod
    def get_user_permissions(user_role: str) -> list:
        """Get list of permissions for a role"""
        try:
            return RBACManager.ROLES.get(user_role, {}).get('permissions', [])
        except Exception:
            return []
    
    @staticmethod
    def require_permission(permission: str):
        """Decorator to require specific permission"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                if 'user' not in st.session_state:
                    st.error("Please log in to access this feature")
                    return
                
                user_role = st.session_state.user.get('role', 'user')
                if not RBACManager.check_permission(user_role, permission):
                    st.error("You don't have permission to access this feature")
                    return
                
                return func(*args, **kwargs)
            return wrapper
        return decorator

class SessionManager:
    """Session management for user authentication"""
    
    @staticmethod
    def create_session(user_data: dict):
        """Create user session"""
        try:
            st.session_state.user = {
                'id': user_data['id'],
                'full_name': user_data['full_name'],
                'role': user_data['role'],
                'login_time': datetime.now().isoformat()
            }
            st.session_state.authenticated = True
            
        except Exception as e:
            st.error(f"Failed to create session: {str(e)}")
    
    @staticmethod
    def _generate_session_id() -> str:
        """Generate unique session ID"""
        try:
            return hashlib.sha256(f"{datetime.now()}{random.random()}".encode()).hexdigest()[:16]
        except Exception:
            return str(random.randint(100000, 999999))
    
    @staticmethod
    def validate_session() -> bool:
        """Validate current session"""
        try:
            if 'user' not in st.session_state or 'authenticated' not in st.session_state:
                return False
            
            if not st.session_state.authenticated:
                return False
            
            # Check session timeout
            if 'login_time' in st.session_state.user:
                login_time = datetime.fromisoformat(st.session_state.user['login_time'])
                timeout = timedelta(minutes=SECURITY_CONFIG['session_timeout_minutes'])
                
                if datetime.now() - login_time > timeout:
                    SessionManager.clear_session()
                    return False
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def clear_session():
        """Clear user session"""
        try:
            if 'user' in st.session_state:
                del st.session_state.user
            if 'authenticated' in st.session_state:
                del st.session_state.authenticated
        except Exception:
            pass

def initialize_security_database():
    """Initialize security-related database tables"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Security logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Login attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Add encryption columns to users table if they don't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'nin_encrypted' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN nin_encrypted TEXT')
        
        if 'passport_encrypted' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN passport_encrypted TEXT')
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        st.error(f"Failed to initialize security database: {str(e)}")
        return False

def log_security_event(user_id: int, action: str, details: str = None):
    """Log security events"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_logs (user_id, action, details, created_at)
            VALUES (?, ?, ?, ?)
        ''', (user_id, action, details, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        st.error(f"Failed to log security event: {str(e)}")

def check_login_attempts(identifier: str) -> bool:
    """Check if user has exceeded login attempts"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Get recent failed attempts
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts 
            WHERE identifier = ? AND success = 0 
            AND created_at > datetime('now', '-15 minutes')
        ''', (identifier,))
        
        failed_attempts = cursor.fetchone()[0]
        conn.close()
        
        return failed_attempts < SECURITY_CONFIG['max_login_attempts']
        
    except Exception as e:
        st.error(f"Failed to check login attempts: {str(e)}")
        return True

def log_login_attempt(identifier: str, success: bool):
    """Log login attempt"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO login_attempts (identifier, success, created_at)
            VALUES (?, ?, ?)
        ''', (identifier, success, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        st.error(f"Failed to log login attempt: {str(e)}")

def display_captcha() -> bool:
    """Display CAPTCHA and return validation result"""
    if not SECURITY_CONFIG['captcha_enabled']:
        return True
    
    st.markdown("### 🤖 CAPTCHA Verification")
    
    captcha_type = st.selectbox("CAPTCHA Type", ["Math Problem", "Text Code"])
    
    if captcha_type == "Math Problem":
        question, answer = CAPTCHAGenerator.generate_math_captcha()
        st.markdown(f"**Solve this math problem:** {question}")
        
        user_answer = st.number_input("Your answer:", min_value=0, step=1)
        
        if st.button("Verify CAPTCHA"):
            if user_answer == answer:
                st.success("✅ CAPTCHA verified successfully!")
                return True
            else:
                st.error("❌ Incorrect answer. Please try again.")
                return False
    else:
        captcha_text, correct_answer = CAPTCHAGenerator.generate_text_captcha()
        st.markdown(f"**Enter this code:** `{captcha_text}`")
        
        user_input = st.text_input("Enter the code:", max_chars=10).upper()
        
        if st.button("Verify CAPTCHA"):
            if user_input == correct_answer:
                st.success("✅ CAPTCHA verified successfully!")
                return True
            else:
                st.error("❌ Incorrect code. Please try again.")
                return False
    
    return False

def display_security_settings():
    """Display security configuration interface"""
    st.markdown("## 🔐 Security Settings")
    
    # Security configuration
    with st.expander("⚙️ Security Configuration", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            SECURITY_CONFIG['encryption_enabled'] = st.checkbox(
                "Enable Encryption", 
                value=SECURITY_CONFIG['encryption_enabled']
            )
            
            SECURITY_CONFIG['captcha_enabled'] = st.checkbox(
                "Enable CAPTCHA", 
                value=SECURITY_CONFIG['captcha_enabled']
            )
            
            SECURITY_CONFIG['session_timeout_minutes'] = st.number_input(
                "Session Timeout (minutes)",
                min_value=5,
                max_value=1440,
                value=SECURITY_CONFIG['session_timeout_minutes']
            )
        
        with col2:
            SECURITY_CONFIG['max_login_attempts'] = st.number_input(
                "Max Login Attempts",
                min_value=1,
                max_value=10,
                value=SECURITY_CONFIG['max_login_attempts']
            )
            
            SECURITY_CONFIG['password_min_length'] = st.number_input(
                "Min Password Length",
                min_value=6,
                max_value=20,
                value=SECURITY_CONFIG['password_min_length']
            )
            
            SECURITY_CONFIG['require_special_chars'] = st.checkbox(
                "Require Special Characters",
                value=SECURITY_CONFIG['require_special_chars']
            )
    
    # Security status
    with st.expander("📊 Security Status", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Encryption Status:**")
            if CRYPTOGRAPHY_AVAILABLE:
                st.success("✅ Cryptography library available")
            else:
                st.warning("⚠️ Using fallback encryption")
            
            st.markdown("**Database Security:**")
            st.info("✅ SQLite with basic security")
        
        with col2:
            st.markdown("**Session Management:**")
            if SessionManager.validate_session():
                st.success("✅ Active session")
            else:
                st.info("ℹ️ No active session")
            
            st.markdown("**RBAC System:**")
            st.success("✅ Role-based access control active")
    
    # Security logs
    with st.expander("📋 Recent Security Logs", expanded=False):
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT action, details, created_at
                FROM security_logs
                ORDER BY created_at DESC
                LIMIT 10
            ''')
            
            logs = cursor.fetchall()
            conn.close()
            
            if logs:
                for log in logs:
                    st.markdown(f"**{log[0]}** - {log[2]}")
                    if log[1]:
                        st.markdown(f"*{log[1]}*")
                    st.divider()
            else:
                st.info("No security logs found")
                
        except Exception as e:
            st.error(f"Failed to load security logs: {str(e)}")

def main():
    """Main function for security module"""
    st.set_page_config(
        page_title="Security Module",
        page_icon="🔐",
        layout="wide"
    )
    
    st.title("🔐 Security Module")
    st.markdown("Comprehensive security features for the Road Risk Reporter")
    
    # Initialize security
    security_manager = SecurityManager()
    
    # Initialize database
    if initialize_security_database():
        st.success("✅ Security database initialized")
    
    # Display security interface
    display_security_settings()
    
    # Test CAPTCHA
    with st.expander("🧪 Test CAPTCHA", expanded=False):
        if display_captcha():
            st.success("CAPTCHA test passed!")

if __name__ == "__main__":
    main() 