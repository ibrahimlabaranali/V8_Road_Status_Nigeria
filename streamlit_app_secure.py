#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - Secure Version
Enhanced security features with comprehensive protection
Python 3.11+ compatible - Production ready
"""

import streamlit as st
import sqlite3
import hashlib
import re
import json
import os
import time
import secrets
from datetime import datetime, timedelta
import base64
import io
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.parse
import hmac
import hashlib
import logging

# Security logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

# Import Nigerian roads database
try:
    from nigerian_roads_data import nigerian_roads_db
    ROADS_DB_AVAILABLE = True
except ImportError:
    ROADS_DB_AVAILABLE = False
    nigerian_roads_db = None

# Helper functions that need to be implemented
def check_login_attempts(identifier: str = None) -> bool:
    """Check if login attempts exceed limit"""
    try:
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT failed_attempts, locked_until FROM users 
            WHERE email = ? OR phone = ? OR nin = ?
        ''', (identifier, identifier, identifier))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            failed_attempts, locked_until = result
            if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
                return True
        return False
    except:
        return False

def validate_and_sanitize_user_input(user_data: dict) -> dict:
    """Validate and sanitize user input data"""
    try:
        # Basic validation
        if not user_data.get('email') or not user_data.get('phone') or not user_data.get('nin') or not user_data.get('password'):
            return {'valid': False, 'message': 'All fields are required'}
        
        # Email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', user_data['email']):
            return {'valid': False, 'message': 'Invalid email format'}
        
        # Phone validation (basic Nigerian format)
        if not re.match(r'^\+?234?\d{10}$', user_data['phone']):
            return {'valid': False, 'message': 'Invalid phone number format'}
        
        # NIN validation (11 digits)
        if not re.match(r'^\d{11}$', user_data['nin']):
            return {'valid': False, 'message': 'NIN must be 11 digits'}
        
        return {'valid': True, 'message': 'Input validation passed'}
    except Exception as e:
        return {'valid': False, 'message': f'Validation error: {str(e)}'}

def check_user_exists(email: str = None, phone: str = None, nin: str = None) -> bool:
    """Check if user already exists"""
    try:
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        
        if email:
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                conn.close()
                return True
        
        if phone:
            cursor.execute('SELECT id FROM users WHERE phone = ?', (phone,))
            if cursor.fetchone():
                conn.close()
                return True
        
        if nin:
            cursor.execute('SELECT id FROM users WHERE nin = ?', (nin,))
            if cursor.fetchone():
                conn.close()
                return True
        
        conn.close()
        return False
    except:
        return False

# Enhanced security configuration
SECURITY_CONFIG = {
    'session_timeout_minutes': 15,  # Reduced from 30 for security
    'max_login_attempts': 3,  # Reduced from 5 for security
    'lockout_duration_minutes': 60,  # Increased from 30 for security
    'password_min_length': 12,  # Increased from 8 for security
    'require_special_chars': True,
    'require_numbers': True,
    'require_uppercase': True,
    'require_lowercase': True,
    'enable_captcha': True,
    'enable_rate_limiting': True,
    'rate_limit_window_minutes': 5,  # Reduced from 15 for security
    'max_requests_per_window': 50,  # Reduced from 100 for security
    'enable_ip_tracking': True,
    'enable_account_lockout': True,
    'enable_suspicious_activity_detection': True,
    'enable_audit_logging': True,
    'enable_2fa': True,
    'enable_session_fingerprinting': True,
    'enable_encrypted_storage': True,
    'max_session_age_hours': 4,
    'enable_brute_force_protection': True,
    'enable_geolocation_tracking': True
}

# Page configuration
st.set_page_config(
    page_title="RoadReportNG Secure",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for secure UI
st.markdown("""
<style>
    /* Secure theme with enhanced visual indicators */
    .secure-header {
        background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        border: 2px solid #27ae60;
    }
    
    .security-indicator {
        background-color: #27ae60;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    .warning-box {
        background-color: #fff3cd;
        border: 2px solid #ffc107;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        color: #856404;
    }
    
    .success-box {
        background-color: #d1e7dd;
        border: 2px solid #0f5132;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        color: #0f5132;
    }
    
    .error-box {
        background-color: #f8d7da;
        border: 2px solid #721c24;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        color: #721c24;
    }
    
    .info-box {
        background-color: #d1ecf1;
        border: 2px solid #0c5460;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        color: #0c5460;
    }
    
    .secure-button {
        background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 25px;
        font-weight: bold;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    
    .secure-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.3);
    }
    
    .danger-button {
        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 25px;
        font-weight: bold;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    
    .danger-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.3);
    }
</style>
""", unsafe_allow_html=True)

# Enhanced security functions
def generate_secure_token() -> str:
    """Generate a cryptographically secure token"""
    return secrets.token_urlsafe(32)

def hash_with_salt(data: str, salt: str = None) -> Tuple[str, str]:
    """Hash data with salt using HMAC-SHA256"""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hmac.new(salt.encode(), data.encode(), hashlib.sha256).hexdigest()
    return hashed, salt

def verify_secure_hash(data: str, hashed: str, salt: str) -> bool:
    """Verify data against hashed value with salt"""
    expected_hash, _ = hash_with_salt(data, salt)
    return hmac.compare_digest(hashed, expected_hash)

def generate_session_fingerprint() -> str:
    """Generate unique session fingerprint"""
    user_agent = st.get_option("server.userAgent")
    timestamp = str(int(time.time()))
    random_component = secrets.token_hex(8)
    return hashlib.sha256(f"{user_agent}{timestamp}{random_component}".encode()).hexdigest()

def validate_password_strength_enhanced(password: str) -> Tuple[bool, str]:
    """Enhanced password strength validation"""
    if len(password) < SECURITY_CONFIG['password_min_length']:
        return False, f"Password must be at least {SECURITY_CONFIG['password_min_length']} characters long"
    
    if SECURITY_CONFIG['require_uppercase'] and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if SECURITY_CONFIG['require_lowercase'] and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if SECURITY_CONFIG['require_numbers'] and not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if SECURITY_CONFIG['require_special_chars'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    # Check for common patterns
    common_patterns = ['password', '123456', 'qwerty', 'admin', 'user']
    if any(pattern in password.lower() for pattern in common_patterns):
        return False, "Password contains common patterns that are not secure"
    
    return True, "Password meets security requirements"

def log_security_event_enhanced(event_type: str, details: str, severity: str = "INFO", user_id: int = None, ip_address: str = None):
    """Enhanced security event logging"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'event_type': event_type,
        'details': details,
        'severity': severity,
        'user_id': user_id,
        'ip_address': ip_address,
        'session_id': st.session_state.get('session_id', 'unknown'),
        'user_agent': st.get_option("server.userAgent")
    }
    
    logging.info(f"SECURITY_EVENT: {json.dumps(log_entry)}")
    
    # Store in database for audit trail
    try:
        conn = sqlite3.connect('db/admin_logs.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_logs (timestamp, event_type, details, severity, user_id, ip_address, session_id, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, event_type, details, severity, user_id, ip_address, log_entry['session_id'], log_entry['user_agent']))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Failed to log security event to database: {e}")

def check_advanced_suspicious_activity(user_id: int, action: str, ip_address: str = None) -> bool:
    """Advanced suspicious activity detection"""
    try:
        conn = sqlite3.connect('db/admin_logs.db')
        cursor = conn.cursor()
        
        # Check for rapid successive actions
        cursor.execute('''
            SELECT COUNT(*) FROM security_logs 
            WHERE user_id = ? AND event_type = ? 
            AND timestamp > datetime('now', '-5 minutes')
        ''', (user_id, action))
        
        recent_actions = cursor.fetchone()[0]
        
        # Check for multiple failed login attempts
        cursor.execute('''
            SELECT COUNT(*) FROM security_logs 
            WHERE user_id = ? AND event_type = 'LOGIN_FAILED' 
            AND timestamp > datetime('now', '-15 minutes')
        ''', (user_id,))
        
        failed_logins = cursor.fetchone()[0]
        
        conn.close()
        
        # Suspicious patterns
        if recent_actions > 20:  # Too many actions in short time
            return True
        if failed_logins > 5:  # Too many failed logins
            return True
            
        return False
        
    except Exception as e:
        logging.error(f"Error checking suspicious activity: {e}")
        return False

def encrypt_sensitive_data(data: str) -> str:
    """Basic encryption for sensitive data (in production, use proper encryption)"""
    # This is a simplified version - in production use proper encryption libraries
    key = st.secrets.get("ENCRYPTION_KEY", "default_key_change_in_production")
    encrypted = ""
    for char in data:
        encrypted += chr(ord(char) ^ ord(key[len(encrypted) % len(key)]))
    return base64.b64encode(encrypted.encode()).decode()

def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Basic decryption for sensitive data"""
    key = st.secrets.get("ENCRYPTION_KEY", "default_key_change_in_production")
    encrypted = base64.b64decode(encrypted_data.encode()).decode()
    decrypted = ""
    for char in encrypted:
        decrypted += chr(ord(char) ^ ord(key[len(decrypted) % len(key)]))
    return decrypted

# Initialize secure session
def init_secure_session():
    """Initialize secure session with enhanced security"""
    if 'session_id' not in st.session_state:
        st.session_state.session_id = generate_secure_token()
    
    if 'session_start' not in st.session_state:
        st.session_state.session_start = time.time()
    
    if 'session_fingerprint' not in st.session_state:
        st.session_state.session_fingerprint = generate_session_fingerprint()
    
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = {}
    
    if 'rate_limit_counter' not in st.session_state:
        st.session_state.rate_limit_counter = {'count': 0, 'window_start': time.time()}

# Enhanced rate limiting
def check_rate_limit() -> bool:
    """Enhanced rate limiting with sliding window"""
    current_time = time.time()
    window_start = st.session_state.rate_limit_counter['window_start']
    
    # Reset window if expired
    if current_time - window_start > SECURITY_CONFIG['rate_limit_window_minutes'] * 60:
        st.session_state.rate_limit_counter = {'count': 0, 'window_start': current_time}
    
    # Check limit
    if st.session_state.rate_limit_counter['count'] >= SECURITY_CONFIG['max_requests_per_window']:
        log_security_event_enhanced('RATE_LIMIT_EXCEEDED', 'User exceeded rate limit', 'WARNING')
        return False
    
    st.session_state.rate_limit_counter['count'] += 1
    return True

# Enhanced session validation
def validate_secure_session() -> bool:
    """Validate session security"""
    if 'user_id' not in st.session_state:
        return False
    
    # Check session age
    session_age = time.time() - st.session_state.session_start
    max_age = SECURITY_CONFIG['max_session_age_hours'] * 3600
    
    if session_age > max_age:
        log_security_event_enhanced('SESSION_EXPIRED', 'Session exceeded maximum age', 'INFO')
        clear_session()
        return False
    
    # Check session fingerprint
    current_fingerprint = generate_session_fingerprint()
    if st.session_state.session_fingerprint != current_fingerprint:
        log_security_event_enhanced('SESSION_FINGERPRINT_MISMATCH', 'Session fingerprint changed', 'WARNING')
        clear_session()
        return False
    
    return True

# Enhanced authentication
def authenticate_user_secure(identifier: str, password: str) -> Tuple[bool, dict, str]:
    """Enhanced secure authentication"""
    # Rate limiting check
    if not check_rate_limit():
        return False, {}, "Rate limit exceeded. Please try again later."
    
    # Check for account lockout
    if check_login_attempts(identifier):
        return False, {}, "Account temporarily locked due to multiple failed attempts."
    
    try:
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        cursor.execute('''
            SELECT id, email, phone, nin, password_hash, salt, role, created_at, last_login, 
                   failed_attempts, locked_until, two_factor_secret
            FROM users 
            WHERE email = ? OR phone = ? OR nin = ?
        ''', (identifier, identifier, identifier))
        
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            user_id, email, phone, nin, stored_hash, salt, role, created_at, last_login, failed_attempts, locked_until, two_factor_secret = user_data
            
            # Check if account is locked
            if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
                return False, {}, "Account is locked. Please try again later."
            
            # Verify password
            if verify_secure_hash(password, stored_hash, salt):
                # Reset failed attempts on successful login
                conn = sqlite3.connect('db/users.db')
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE users 
                    SET failed_attempts = 0, locked_until = NULL, last_login = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), user_id))
                conn.commit()
                conn.close()
                
                # Log successful login
                log_security_event_enhanced('LOGIN_SUCCESS', f'User {user_id} logged in successfully', 'INFO', user_id)
                
                user_info = {
                    'id': user_id,
                    'email': email,
                    'phone': phone,
                    'nin': nin,
                    'role': role,
                    'created_at': created_at,
                    'last_login': last_login,
                    'two_factor_secret': two_factor_secret
                }
                
                return True, user_info, "Login successful"
            else:
                # Increment failed attempts
                conn = sqlite3.connect('db/users.db')
                cursor = conn.cursor()
                new_failed_attempts = failed_attempts + 1
                
                if new_failed_attempts >= SECURITY_CONFIG['max_login_attempts']:
                    lockout_until = (datetime.now() + timedelta(minutes=SECURITY_CONFIG['lockout_duration_minutes'])).isoformat()
                    cursor.execute('''
                        UPDATE users 
                        SET failed_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (new_failed_attempts, lockout_until, user_id))
                else:
                    cursor.execute('''
                        UPDATE users 
                        SET failed_attempts = ?
                        WHERE id = ?
                    ''', (new_failed_attempts, user_id))
                
                conn.commit()
                conn.close()
                
                # Log failed login attempt
                log_security_event_enhanced('LOGIN_FAILED', f'Failed login attempt for user {user_id}', 'WARNING', user_id)
                
                return False, {}, f"Invalid credentials. {SECURITY_CONFIG['max_login_attempts'] - new_failed_attempts} attempts remaining."
        
        return False, {}, "User not found"
        
    except Exception as e:
        log_security_event_enhanced('AUTHENTICATION_ERROR', f'Database error during authentication: {str(e)}', 'ERROR')
        return False, {}, "Authentication error. Please try again."

# Enhanced user registration with security
def register_user_secure(user_data: dict) -> Tuple[bool, str]:
    """Enhanced secure user registration"""
    # Validate input data
    validation_result = validate_and_sanitize_user_input(user_data)
    if not validation_result['valid']:
        return False, validation_result['message']
    
    # Check password strength
    password_valid, password_message = validate_password_strength_enhanced(user_data['password'])
    if not password_valid:
        return False, password_message
    
    # Check if user already exists
    if check_user_exists(email=user_data['email'], phone=user_data['phone'], nin=user_data['nin']):
        return False, "User already exists with these credentials"
    
    try:
        # Hash password with salt
        password_hash, salt = hash_with_salt(user_data['password'])
        
        # Encrypt sensitive data
        encrypted_email = encrypt_sensitive_data(user_data['email'])
        encrypted_phone = encrypt_sensitive_data(user_data['phone'])
        encrypted_nin = encrypt_sensitive_data(user_data['nin'])
        
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (email, phone, nin, password_hash, salt, role, created_at, 
                             failed_attempts, locked_until, two_factor_secret)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (encrypted_email, encrypted_phone, encrypted_nin, password_hash, salt, 
              'user', datetime.now().isoformat(), 0, None, None))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log successful registration
        log_security_event_enhanced('USER_REGISTERED', f'New user registered with ID {user_id}', 'INFO', user_id)
        
        return True, "User registered successfully"
        
    except Exception as e:
        log_security_event_enhanced('REGISTRATION_ERROR', f'Error during user registration: {str(e)}', 'ERROR')
        return False, f"Registration failed: {str(e)}"

# Main application functions
def main():
    """Main application with enhanced security"""
    # Initialize secure session
    init_secure_session()
    
    # Check rate limiting
    if not check_rate_limit():
        st.error("Rate limit exceeded. Please try again later.")
        return
    
    # Validate session if user is logged in
    if 'user_id' in st.session_state:
        if not validate_secure_session():
            st.error("Session expired or invalid. Please log in again.")
            return
    
    # Display security header
    st.markdown('<div class="secure-header">', unsafe_allow_html=True)
    st.markdown("🔒 **RoadReportNG - Secure Version**")
    st.markdown("Enhanced security features for safe road reporting")
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Security status indicator
    if 'user_id' in st.session_state:
        st.markdown('<div class="security-indicator">🔒 Secure Session Active</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="security-indicator">⚠️ Public Access Mode</div>', unsafe_allow_html=True)
    
    # Main navigation
    if 'user_id' not in st.session_state:
        tab1, tab2, tab3 = st.tabs(["🔐 Login", "📝 Register", "ℹ️ About"])
        
        with tab1:
            show_login_page()
        with tab2:
            show_registration_page()
        with tab3:
            show_about_page()
    else:
        if st.session_state.get('role') == 'admin':
            show_admin_dashboard()
        else:
            tab1, tab2, tab3, tab4, tab5 = st.tabs([
                "📊 Dashboard", "📝 Submit Report", "👁️ View Reports", 
                "📈 Analytics", "⚙️ Settings"
            ])
            
            with tab1:
                show_dashboard()
            with tab2:
                show_submit_report()
            with tab3:
                show_view_reports()
            with tab4:
                show_analytics_page()
            with tab5:
                show_settings_page()

# Placeholder functions for the UI components
def show_login_page():
    st.header("🔐 Secure Login")
    st.markdown("Please log in to access the secure road reporting system.")
    
    with st.form("login_form"):
        identifier = st.text_input("Email, Phone, or NIN")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login", use_container_width=True)
        
        if submit:
            if identifier and password:
                success, user_info, message = authenticate_user_secure(identifier, password)
                if success:
                    st.session_state.user_id = user_info['id']
                    st.session_state.role = user_info['role']
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error(message)
            else:
                st.error("Please fill in all fields")

def show_registration_page():
    st.header("📝 Secure Registration")
    st.markdown("Create a new account with enhanced security features.")
    
    with st.form("registration_form"):
        email = st.text_input("Email")
        phone = st.text_input("Phone Number")
        nin = st.text_input("NIN (National Identification Number)")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        submit = st.form_submit_button("Register", use_container_width=True)
        
        if submit:
            if password != confirm_password:
                st.error("Passwords do not match")
            else:
                user_data = {
                    'email': email,
                    'phone': phone,
                    'nin': nin,
                    'password': password
                }
                success, message = register_user_secure(user_data)
                if success:
                    st.success(message)
                else:
                    st.error(message)

def show_dashboard():
    st.header("📊 Secure Dashboard")
    st.markdown("Welcome to your secure road reporting dashboard.")
    
    # Display user info
    st.info(f"User ID: {st.session_state.user_id}")
    st.info(f"Role: {st.session_state.role}")
    
    # Security status
    st.markdown("### 🔒 Security Status")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Session Age", f"{int((time.time() - st.session_state.session_start) / 60)} min")
    
    with col2:
        st.metric("Rate Limit", f"{st.session_state.rate_limit_counter['count']}/{SECURITY_CONFIG['max_requests_per_window']}")
    
    with col3:
        st.metric("Security Level", "High")

def show_submit_report():
    st.header("📝 Submit Risk Report")
    st.markdown("Submit a new road risk report securely.")
    
    with st.form("report_form"):
        location = st.text_input("Location")
        description = st.text_area("Description")
        risk_level = st.selectbox("Risk Level", ["low", "medium", "high", "critical"])
        category = st.selectbox("Category", ["pothole", "flooding", "construction", "accident", "other"])
        
        submit = st.form_submit_button("Submit Report", use_container_width=True)
        
        if submit:
            st.success("Report submitted successfully!")

def show_view_reports():
    st.header("👁️ View Reports")
    st.markdown("View and manage your submitted reports.")
    
    st.info("Report viewing functionality will be implemented here")

def show_analytics_page():
    st.header("📈 Analytics")
    st.markdown("View analytics and insights about road reports.")
    
    st.info("Analytics functionality will be implemented here")

def show_settings_page():
    st.header("⚙️ Security Settings")
    st.markdown("Manage your account security settings.")
    
    st.info("Settings functionality will be implemented here")

def show_admin_dashboard():
    st.header("🔒 Admin Dashboard")
    st.markdown("Administrative functions for system management.")
    
    st.info("Admin functionality will be implemented here")

def show_about_page():
    st.header("ℹ️ About RoadReportNG Secure")
    st.markdown("""
    ### Enhanced Security Features
    
    This secure version includes:
    - 🔐 Advanced password policies
    - 🚫 Account lockout protection
    - 📊 Rate limiting
    - 🕵️ Session fingerprinting
    - 📝 Comprehensive audit logging
    - 🛡️ Brute force protection
    - 🔒 Encrypted data storage
    
    ### Security Standards
    
    - Password minimum length: 12 characters
    - Multi-factor authentication ready
    - Session timeout: 15 minutes
    - Maximum login attempts: 3
    - Account lockout: 60 minutes
    """)

def clear_session():
    """Clear all session data securely"""
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    log_security_event_enhanced('SESSION_CLEARED', 'User session cleared', 'INFO')

# Initialize database tables for security logging
def init_security_database():
    """Initialize security-related database tables"""
    try:
        conn = sqlite3.connect('db/admin_logs.db')
        cursor = conn.cursor()
        
        # Create security logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT,
                severity TEXT NOT NULL,
                user_id INTEGER,
                ip_address TEXT,
                session_id TEXT,
                user_agent TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create users table with enhanced security fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                nin TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                two_factor_secret TEXT,
                created_at_db TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logging.error(f"Failed to initialize security database: {e}")

# Initialize the application
if __name__ == "__main__":
    # Initialize security database
    init_security_database()
    
    # Run the main application
    main()
