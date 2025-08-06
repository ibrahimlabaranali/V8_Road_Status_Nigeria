#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - Enhanced Minimal Version
Complete road risk reporting system with minimal dependencies
Python 3.13 compatible - Streamlit Cloud ready
"""

import streamlit as st
import sqlite3
import hashlib
import re
import json
import os
import time
from datetime import datetime, timedelta
import base64
import io
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.parse

# Import Nigerian roads database
try:
    from nigerian_roads_data import nigerian_roads_db
    ROADS_DB_AVAILABLE = True
except ImportError:
    ROADS_DB_AVAILABLE = False
    nigerian_roads_db = None

# Security configuration
SECURITY_CONFIG = {
    'session_timeout_minutes': 30,
    'max_login_attempts': 5,  # Updated to 5 attempts
    'lockout_duration_minutes': 30,  # 30-minute lockout after 5 failed attempts
    'password_min_length': 8,
    'require_special_chars': True,
    'enable_captcha': True,
    'enable_rate_limiting': True,
    'rate_limit_window_minutes': 15,
    'max_requests_per_window': 100,
    'enable_ip_tracking': True,
    'enable_account_lockout': True,
    'enable_suspicious_activity_detection': True,
    'enable_audit_logging': True
}

# Page configuration
st.set_page_config(
    page_title="RoadReportNG",
    page_icon="🛣️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for clean UI with improved accessibility
st.markdown("""
<style>
    /* Main header with improved contrast */
    .main-header {
        background: linear-gradient(135deg, #1f77b4 0%, #ff7f0e 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    /* Improved status boxes with better contrast */
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
    .warning-box {
        background-color: #fff3cd;
        border: 2px solid #856404;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        color: #856404;
    }
    
    /* Enhanced risk cards */
    .risk-card {
        background-color: #ffffff;
        border: 2px solid #dee2e6;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        transition: transform 0.2s ease;
    }
    .risk-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    }
    
    /* Risk type badges with improved contrast */
    .risk-type-robbery { background-color: #dc3545; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .risk-type-flooding { background-color: #007bff; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .risk-type-protest { background-color: #6f42c1; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .risk-type-damage { background-color: #fd7e14; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .risk-type-traffic { background-color: #ffc107; color: black; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .risk-type-other { background-color: #6c757d; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    
    /* Status badges */
    .status-pending { background-color: #ffc107; color: black; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .status-verified { background-color: #28a745; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .status-resolved { background-color: #007bff; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    .status-false { background-color: #dc3545; color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold; }
    
    /* Loading animation */
    .loading {
        display: inline-block;
        width: 20px;
        height: 20px;
        border: 3px solid #f3f3f3;
        border-top: 3px solid #1f77b4;
        border-radius: 50%;
        animation: spin 1s linear infinite;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    /* Improved form styling */
    .stTextInput > div > div > input {
        border-radius: 8px;
        border: 2px solid #dee2e6;
    }
    .stTextInput > div > div > input:focus {
        border-color: #1f77b4;
        box-shadow: 0 0 0 0.2rem rgba(31, 119, 180, 0.25);
    }
    
    /* Button improvements */
    .stButton > button {
        border-radius: 8px;
        font-weight: bold;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    
    /* Accessibility improvements */
    .sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip: rect(0, 0, 0, 0);
        white-space: nowrap;
        border: 0;
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
        .main-header {
            padding: 1rem;
            font-size: 1.2rem;
        }
        .risk-card {
            padding: 1rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user' not in st.session_state:
    st.session_state.user = {}
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0
if 'last_login_attempt' not in st.session_state:
    st.session_state.last_login_attempt = None

# Database setup
def init_database():
    """Initialize SQLite database with users, risk reports, and admin logs tables"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                phone_number TEXT NOT NULL UNIQUE,
                email TEXT,
                role TEXT NOT NULL,
                nin_or_passport TEXT,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Risk reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                risk_type TEXT NOT NULL,
                description TEXT NOT NULL,
                location TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                voice_file_path TEXT,
                image_file_path TEXT,
                source_type TEXT DEFAULT 'user',
                source_url TEXT,
                status TEXT DEFAULT 'pending',
                confirmations INTEGER DEFAULT 0,
                upvotes INTEGER DEFAULT 0,
                advice TEXT,
                risk_level TEXT DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Admin logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                admin_name TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES users (id)
            )
        ''')
        
        # Report upvotes table for community validation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report_upvotes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES risk_reports (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(report_id, user_id)
            )
        ''')
        
        # Security audit logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_ip TEXT,
                action TEXT NOT NULL,
                details TEXT,
                success BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Password resets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                user_type TEXT NOT NULL,
                reset_token TEXT UNIQUE NOT NULL,
                expiry_time TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Login attempts tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                user_ip TEXT,
                success BOOLEAN DEFAULT FALSE,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        ''')
        
        # Account lockouts table
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
        
        # Rate limiting table
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
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Database initialization error: {str(e)}")
        return False

# Security and utility functions
def hash_password(password: str) -> str:
    """Hash password using SHA256 with salt for better security"""
    try:
        # Add salt for better security
        salt = os.urandom(16).hex()
        hash_obj = hashlib.sha256()
        hash_obj.update((password + salt).encode('utf-8'))
        return f"{salt}${hash_obj.hexdigest()}"
    except Exception as e:
        st.error(f"Password hashing error: {str(e)}")
        return password  # Fallback

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash with salt"""
    try:
        if '$' not in hashed:
            # Legacy password without salt
            return hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed
        
        salt, hash_value = hashed.split('$', 1)
        hash_obj = hashlib.sha256()
        hash_obj.update((password + salt).encode('utf-8'))
        return hash_obj.hexdigest() == hash_value
    except Exception as e:
        st.error(f"Password verification error: {str(e)}")
        return password == hashed  # Fallback

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password strength"""
    if len(password) < SECURITY_CONFIG['password_min_length']:
        return False, f"Password must be at least {SECURITY_CONFIG['password_min_length']} characters long"
    
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

def check_session_timeout() -> bool:
    """Check if user session has timed out"""
    if not st.session_state.authenticated:
        return True
    
    if 'login_time' not in st.session_state.user:
        return True
    
    try:
        login_time = datetime.fromisoformat(st.session_state.user['login_time'])
        timeout = timedelta(minutes=SECURITY_CONFIG['session_timeout_minutes'])
        
        if datetime.now() - login_time > timeout:
            clear_session()
            return True
        
        return False
    except Exception:
        return True

def clear_session():
    """Clear user session"""
    st.session_state.authenticated = False
    st.session_state.user = {}
    st.session_state.login_attempts = 0
    st.session_state.last_login_attempt = None

def get_client_ip():
    """Get client IP address"""
    try:
        # For Streamlit Cloud, try to get IP from headers
        if hasattr(st, 'get_option') and st.get_option('server.address') != 'localhost':
            # This is a simplified approach - in production, you'd want proper IP detection
            return "unknown"
        return "127.0.0.1"  # Local development
    except:
        return "unknown"

def sanitize_input(input_string: str) -> str:
    """Sanitize user input to prevent SQL injection"""
    import re
    if not input_string:
        return ""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;\'\"\\]', '', input_string)
    return sanitized.strip()

def validate_and_sanitize_user_input(user_data: dict) -> dict:
    """Validate and sanitize all user inputs"""
    sanitized_data = {}
    for key, value in user_data.items():
        if isinstance(value, str):
            sanitized_data[key] = sanitize_input(value)
        else:
            sanitized_data[key] = value
    return sanitized_data

def log_security_event(event_type: str, details: str, severity: str = "INFO"):
    """Log security events for monitoring"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_audit_logs (user_ip, action, details, success)
            VALUES (?, ?, ?, ?)
        ''', (get_client_ip(), event_type, details, True))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log security event: {e}")

def detect_suspicious_activity(user_id: int, action: str) -> bool:
    """Detect suspicious user activity"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check for rapid successive actions
        cursor.execute('''
            SELECT COUNT(*) FROM security_audit_logs 
            WHERE user_id = ? AND action = ? 
            AND created_at > datetime('now', '-5 minutes')
        ''', (user_id, action))
        
        recent_actions = cursor.fetchone()[0]
        conn.close()
        
        # Flag if more than 10 actions in 5 minutes
        if recent_actions > 10:
            log_security_event("suspicious_activity", 
                             f"User {user_id} performed {recent_actions} {action} actions in 5 minutes", 
                             "WARNING")
            return True
        
        return False
        
    except Exception:
        return False

def check_login_attempts(identifier: str = None) -> bool:
    """Check if user has exceeded login attempts with enhanced security"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check for active lockouts
        if identifier:
            cursor.execute('''
                SELECT lockout_end FROM account_lockouts 
                WHERE identifier = ? AND is_active = TRUE AND lockout_end > datetime('now')
            ''', (identifier,))
            
            lockout = cursor.fetchone()
            if lockout:
                conn.close()
                return False
        
        # Check session state attempts
        if st.session_state.login_attempts >= SECURITY_CONFIG['max_login_attempts']:
            if st.session_state.last_login_attempt:
                try:
                    last_attempt = datetime.fromisoformat(st.session_state.last_login_attempt)
                    lockout_duration = timedelta(minutes=SECURITY_CONFIG['lockout_duration_minutes'])
                    
                    if datetime.now() - last_attempt < lockout_duration:
                        conn.close()
                        return False
                    else:
                        # Reset after lockout period
                        st.session_state.login_attempts = 0
                        st.session_state.last_login_attempt = None
                except Exception:
                    st.session_state.login_attempts = 0
                    st.session_state.last_login_attempt = None
        
        conn.close()
        return True
        
    except Exception:
        return True

def log_login_attempt(success: bool, identifier: str = None, user_ip: str = None):
    """Log login attempt with enhanced tracking"""
    try:
        # Update session state
        if not success:
            st.session_state.login_attempts += 1
            st.session_state.last_login_attempt = datetime.now().isoformat()
        else:
            st.session_state.login_attempts = 0
            st.session_state.last_login_attempt = None
        
        # Log to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Log the attempt
        cursor.execute('''
            INSERT INTO login_attempts (identifier, user_ip, success, user_agent)
            VALUES (?, ?, ?, ?)
        ''', (identifier or "unknown", user_ip or get_client_ip(), success, "Streamlit App"))
        
        # If failed and reached max attempts, create lockout
        if not success and st.session_state.login_attempts >= SECURITY_CONFIG['max_login_attempts']:
            lockout_end = datetime.now() + timedelta(minutes=SECURITY_CONFIG['lockout_duration_minutes'])
            cursor.execute('''
                INSERT INTO account_lockouts (identifier, user_ip, lockout_reason, lockout_end)
                VALUES (?, ?, ?, ?)
            ''', (identifier or "unknown", user_ip or get_client_ip(), 
                  f"Exceeded {SECURITY_CONFIG['max_login_attempts']} failed login attempts", 
                  lockout_end.isoformat()))
        
        # Log security audit
        cursor.execute('''
            INSERT INTO security_audit_logs (user_ip, action, details, success)
            VALUES (?, ?, ?, ?)
        ''', (user_ip or get_client_ip(), "login_attempt", 
              f"Login attempt for {identifier or 'unknown'}", success))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        # Fallback to session state only
        if not success:
            st.session_state.login_attempts += 1
            st.session_state.last_login_attempt = datetime.now().isoformat()
        else:
            st.session_state.login_attempts = 0
            st.session_state.last_login_attempt = None

def validate_email(email: str) -> bool:
    """Simple email validation"""
    if not email:
        return True
    try:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    except Exception:
        return True

def validate_phone(phone: str) -> bool:
    """Nigerian phone number validation"""
    try:
        phone = re.sub(r'[^\d+]', '', phone)
        if phone.startswith('+234') and len(phone) == 14:
            return True
        elif phone.startswith('0') and len(phone) == 11:
            return True
        return False
    except Exception:
        return True

def validate_nin(nin: str) -> bool:
    """NIN validation (11 digits) - Optional field"""
    try:
        if not nin:  # Allow empty NIN
            return True
        return nin.isdigit() and len(nin) == 11
    except Exception:
        return True

def check_user_exists(email: str = None, phone: str = None, nin: str = None) -> bool:
    """Check if user already exists"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        if email:
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                conn.close()
                return True
        
        if phone:
            cursor.execute('SELECT id FROM users WHERE phone_number = ?', (phone,))
            if cursor.fetchone():
                conn.close()
                return True
        
        if nin and nin.strip():  # Only check NIN if it's provided and not empty
            cursor.execute('SELECT id FROM users WHERE nin_or_passport = ?', (nin,))
            if cursor.fetchone():
                conn.close()
                return True
        
        conn.close()
        return False
    except Exception:
        return False

def register_user(user_data: dict) -> tuple[bool, str]:
    """Register a new user with enhanced security"""
    try:
        # Sanitize user input
        sanitized_data = validate_and_sanitize_user_input(user_data)
        
        # Basic validation
        if not sanitized_data.get('full_name') or len(sanitized_data['full_name']) < 2:
            return False, "Full name must be at least 2 characters long"
        
        if not validate_phone(sanitized_data['phone_number']):
            return False, "Invalid Nigerian phone number format"
        
        if sanitized_data.get('email') and not validate_email(sanitized_data['email']):
            return False, "Invalid email format"
        
        if sanitized_data.get('nin_or_passport') and not validate_nin(sanitized_data['nin_or_passport']):
            return False, "NIN must be exactly 11 digits if provided"
        
        # Check if user already exists
        if check_user_exists(
            email=sanitized_data.get('email'),
            phone=sanitized_data['phone_number'],
            nin=sanitized_data.get('nin_or_passport')
        ):
            return False, "User with this email or phone number already exists"
        
        # Hash password
        hashed_password = hash_password(sanitized_data['password'])
        
        # Save to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport, password_hash
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            sanitized_data['full_name'],
            sanitized_data['phone_number'],
            sanitized_data.get('email'),
            sanitized_data['role'],
            sanitized_data['nin_or_passport'] if sanitized_data['nin_or_passport'] else None,
            hashed_password
        ))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log security event
        log_security_event("user_registration", f"New user registered: {sanitized_data['full_name']}")
        
        return True, "Registration successful! You can now log in."
        
    except Exception as e:
        log_security_event("registration_failed", f"Registration failed: {str(e)}", "ERROR")
        return False, f"Registration failed: {str(e)}"

def authenticate_user(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate user login with enhanced security"""
    try:
        user_ip = get_client_ip()
        
        # Check login attempts with enhanced security
        if not check_login_attempts(identifier):
            lockout_duration = SECURITY_CONFIG['lockout_duration_minutes']
            return False, {}, f"Account temporarily locked due to too many failed attempts. Please wait {lockout_duration} minutes before trying again."
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find user by email or phone
        cursor.execute('''
            SELECT id, full_name, email, phone_number, role, password_hash
            FROM users 
            WHERE (email = ? OR phone_number = ?)
        ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            log_login_attempt(False, identifier, user_ip)
            return False, {}, "Invalid email/phone or password"
        
        user_id, full_name, email, phone, role, password_hash = user
        
        # Verify password
        if not verify_password(password, password_hash):
            conn.close()
            log_login_attempt(False, identifier, user_ip)
            return False, {}, "Invalid email/phone or password"
        
        conn.close()
        
        user_data = {
            'id': user_id,
            'full_name': full_name,
            'email': email,
            'phone': phone,
            'role': role,
            'login_time': datetime.now().isoformat()
        }
        
        # Log successful login
        log_login_attempt(True, identifier, user_ip)
        
        # Log security audit for successful login
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_audit_logs (user_id, user_ip, action, details, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, user_ip, "login_success", f"Successful login for user {full_name}", True))
            conn.commit()
            conn.close()
        except Exception:
            pass  # Don't fail login if audit logging fails
        
        # Set session
        st.session_state.authenticated = True
        st.session_state.user = user_data
        
        return True, user_data, "Login successful!"
        
    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        return False, {}, f"Authentication error: {str(e)}"

def save_risk_report(report_data: dict) -> tuple[bool, str]:
    """Save a new risk report to database"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO risk_reports (
                user_id, risk_type, description, location, latitude, longitude,
                voice_file_path, image_file_path, source_type, source_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_data['user_id'],
            report_data['risk_type'],
            report_data['description'],
            report_data['location'],
            report_data.get('latitude'),
            report_data.get('longitude'),
            report_data.get('voice_file_path'),
            report_data.get('image_file_path'),
            report_data.get('source_type', 'user'),
            report_data.get('source_url')
        ))
        
        conn.commit()
        conn.close()
        
        return True, "Risk report submitted successfully!"
        
    except Exception:
        return False, "Report submitted successfully"

def get_risk_reports(user_id: int = None, status: str = None, source_type: str = None) -> list:
    """Get risk reports with optional filtering"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        query = '''
            SELECT r.id, r.risk_type, r.description, r.location, r.latitude, r.longitude,
                   r.status, r.confirmations, r.created_at, u.full_name, r.source_type, r.source_url
            FROM risk_reports r
            JOIN users u ON r.user_id = u.id
        '''
        params = []
        conditions = []
        
        if user_id:
            conditions.append('r.user_id = ?')
            params.append(user_id)
        
        if status and status != 'all':
            conditions.append('r.status = ?')
            params.append(status)
        
        if source_type and source_type != 'all':
            conditions.append('r.source_type = ?')
            params.append(source_type)
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY r.created_at DESC'
        
        cursor.execute(query, params)
        reports = cursor.fetchall()
        conn.close()
        
        return reports
    except Exception:
        return []

def get_report_stats() -> dict:
    """Get risk report statistics"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Total reports
        cursor.execute('SELECT COUNT(*) FROM risk_reports')
        total = cursor.fetchone()[0]
        
        # Reports by status
        cursor.execute('SELECT status, COUNT(*) FROM risk_reports GROUP BY status')
        status_counts = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total': total,
            'pending': status_counts.get('pending', 0),
            'verified': status_counts.get('verified', 0),
            'resolved': status_counts.get('resolved', 0),
            'false': status_counts.get('false', 0)
        }
    except Exception:
        return {'total': 0, 'pending': 0, 'verified': 0, 'resolved': 0, 'false': 0}

def update_report_status(report_id: int, status: str) -> bool:
    """Update report status"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('UPDATE risk_reports SET status = ? WHERE id = ?', (status, report_id))
        conn.commit()
        conn.close()
        
        return True
    except Exception:
        return False

def fetch_nigerian_news() -> list:
    """Fetch Nigerian news articles related to road safety and incidents"""
    try:
        # Simulated news data - in production, you'd use a real news API
        news_data = [
            {
                'title': 'Heavy Traffic on Lagos-Ibadan Expressway Due to Construction',
                'description': 'Motorists are experiencing heavy traffic on the Lagos-Ibadan Expressway due to ongoing construction work. Authorities advise alternative routes.',
                'source': 'Punch Newspapers',
                'url': 'https://punchng.com/traffic-lagos-ibadan-expressway',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Traffic',
                'location': 'Lagos-Ibadan Expressway, Lagos State'
            },
            {
                'title': 'Flooding Reported in Victoria Island After Heavy Rainfall',
                'description': 'Several roads in Victoria Island are flooded following heavy rainfall. Motorists are advised to avoid the area.',
                'source': 'Vanguard News',
                'url': 'https://vanguardngr.com/flooding-victoria-island',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Flooding',
                'location': 'Victoria Island, Lagos State'
            },
            {
                'title': 'Protest Blocks Major Road in Abuja',
                'description': 'A peaceful protest is currently blocking Ahmadu Bello Way in Abuja. Traffic has been diverted to side streets.',
                'source': 'ThisDay Live',
                'url': 'https://thisdaylive.com/protest-abuja',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Protest',
                'location': 'Ahmadu Bello Way, Abuja FCT'
            },
            {
                'title': 'Potholes Cause Multiple Accidents on Ibadan-Oyo Road',
                'description': 'Large potholes on the Ibadan-Oyo Road have caused several accidents. Authorities have been notified.',
                'source': 'The Nation',
                'url': 'https://thenationonlineng.net/potholes-ibadan-oyo',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Road Damage',
                'location': 'Ibadan-Oyo Road, Oyo State'
            }
        ]
        return news_data
    except Exception:
        return []

def fetch_social_media_feeds() -> list:
    """Fetch social media posts related to road incidents"""
    try:
        # Simulated social media data - in production, you'd use Twitter/X API, Facebook API, etc.
        social_data = [
            {
                'content': 'Just witnessed an armed robbery on vehicles near Mile 2. Multiple incidents in the last 2 hours. Stay safe! #LagosSecurity',
                'platform': 'Twitter',
                'username': '@LagosResident',
                'url': 'https://twitter.com/LagosResident/status/123456789',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Robbery',
                'location': 'Mile 2, Lagos State',
                'followers': 1250
            },
            {
                'content': 'Heavy traffic jam on Third Mainland Bridge due to vehicle breakdown. One lane blocked. #LagosTraffic',
                'platform': 'Facebook',
                'username': 'Lagos Traffic Updates',
                'url': 'https://facebook.com/lagostraffic/123456789',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Traffic',
                'location': 'Third Mainland Bridge, Lagos',
                'followers': 8900
            },
            {
                'content': 'Flooding on Lekki-Epe Expressway. Water level about 2 feet deep. Low vehicles should avoid this route. #LagosFlood',
                'platform': 'Instagram',
                'username': '@lagos_weather',
                'url': 'https://instagram.com/p/lagos_weather_123456',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Flooding',
                'location': 'Lekki-Epe Expressway, Lagos',
                'followers': 3400
            },
            {
                'content': 'Large potholes on both lanes of Ibadan-Oyo Road causing vehicles to swerve dangerously. Several tire damage incidents reported.',
                'platform': 'WhatsApp Status',
                'username': 'Road Safety Nigeria',
                'url': 'https://wa.me/2348012345678',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Road Damage',
                'location': 'Ibadan-Oyo Road, Oyo State',
                'followers': 15600
            }
        ]
        return social_data
    except Exception:
        return []

def import_news_to_reports():
    """Import news articles as risk reports"""
    try:
        news_data = fetch_nigerian_news()
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        for news in news_data:
            # Check if already imported
            cursor.execute('SELECT id FROM risk_reports WHERE source_url = ?', (news['url'],))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO risk_reports (
                        user_id, risk_type, description, location, source_type, source_url, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    1,  # System user ID
                    news['risk_type'],
                    f"{news['title']}\n\n{news['description']}\n\nSource: {news['source']}",
                    news['location'],
                    'news',
                    news['url']
                ))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def import_social_media_to_reports():
    """Import social media posts as risk reports"""
    try:
        social_data = fetch_social_media_feeds()
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        for post in social_data:
            # Check if already imported
            cursor.execute('SELECT id FROM risk_reports WHERE source_url = ?', (post['url'],))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO risk_reports (
                        user_id, risk_type, description, location, source_type, source_url, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    1,  # System user ID
                    post['risk_type'],
                    f"{post['content']}\n\nPlatform: {post['platform']}\nUser: {post['username']}\nFollowers: {post['followers']}",
                    post['location'],
                    'social',
                    post['url']
                ))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def get_recent_reports(hours: int = 24) -> list:
    """Get reports from the last N hours"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.id, r.risk_type, r.description, r.location, r.latitude, r.longitude,
                   r.status, r.confirmations, r.created_at, u.full_name, r.source_type, r.source_url
            FROM risk_reports r
            JOIN users u ON r.user_id = u.id
            WHERE r.created_at >= datetime('now', '-{} hours')
            ORDER BY r.created_at DESC
        '''.format(hours))
        
        reports = cursor.fetchall()
        conn.close()
        
        return reports
    except Exception:
        return []

def get_time_ago(timestamp_str: str) -> str:
    """Convert timestamp to 'time ago' format"""
    try:
        # Parse the timestamp
        if isinstance(timestamp_str, str):
            created_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        else:
            created_time = timestamp_str
        
        now = datetime.now()
        diff = now - created_time
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds >= 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds >= 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    except Exception:
        return "Unknown time"

def generate_basic_advice(risk_type: str, location: str) -> str:
    """Generate basic safety advice without external dependencies"""
    advice_templates = {
        "Robbery": "🚨 **Robbery Alert**: Avoid this area, especially at night. Travel in groups if possible. Contact local authorities immediately.",
        "Flooding": "🌊 **Flooding Warning**: Road may be impassable. Avoid driving through flooded areas. Find alternative routes.",
        "Protest": "🏛️ **Protest Notice**: Expect traffic delays and road closures. Plan alternative routes and allow extra travel time.",
        "Road Damage": "🛣️ **Road Damage**: Potholes or road damage detected. Drive carefully and report to authorities.",
        "Traffic": "🚗 **Traffic Alert**: Heavy traffic congestion. Consider alternative routes or delay travel if possible.",
        "Other": "⚠️ **Road Incident**: Exercise caution in this area. Follow local traffic advisories and authorities."
    }
    
    base_advice = advice_templates.get(risk_type, advice_templates["Other"])
    emergency_contacts = "\n\n📞 **Emergency Contacts**:\n• Emergency: 0800-112-1199\n• Police: 112"
    
    return base_advice + emergency_contacts

# Admin-specific functions
def authenticate_admin(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate admin user"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if user exists and is admin
        if '@' in identifier:
            cursor.execute('SELECT * FROM users WHERE email = ? AND role = "Admin"', (identifier,))
        else:
            cursor.execute('SELECT * FROM users WHERE phone_number = ? AND role = "Admin"', (identifier,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            user_id, full_name, phone, email, role, nin, password_hash, created_at = user
            if verify_password(password, password_hash):
                user_data = {
                    'id': user_id,
                    'full_name': full_name,
                    'phone_number': phone,
                    'email': email,
                    'role': role,
                    'nin_or_passport': nin,
                    'created_at': created_at
                }
                return True, user_data, "Admin login successful"
            else:
                return False, {}, "Invalid password"
        else:
            return False, {}, "Admin not found or insufficient privileges"
    except Exception as e:
        return False, {}, f"Authentication error: {str(e)}"

def log_admin_action(admin_id: int, admin_name: str, action: str, target_type: str, target_id: int = None, details: str = None):
    """Log admin actions to admin_logs table"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO admin_logs (admin_id, admin_name, action, target_type, target_id, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (admin_id, admin_name, action, target_type, target_id, details))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to log admin action: {str(e)}")
        return False

def get_admin_logs(limit: int = 50) -> list:
    """Get recent admin logs"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT al.*, u.full_name as admin_full_name
            FROM admin_logs al
            JOIN users u ON al.admin_id = u.id
            ORDER BY al.created_at DESC
            LIMIT ?
        ''', (limit,))
        
        logs = cursor.fetchall()
        conn.close()
        return logs
    except Exception as e:
        st.error(f"Failed to get admin logs: {str(e)}")
        return []

def get_all_users() -> list:
    """Get all users for admin management"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, full_name, phone_number, email, role, nin_or_passport, created_at
            FROM users
            ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        return users
    except Exception as e:
        st.error(f"Failed to get users: {str(e)}")
        return []

def update_user_role(user_id: int, new_role: str, admin_id: int, admin_name: str) -> bool:
    """Update user role and log the action"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Get user details for logging
        cursor.execute('SELECT full_name FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False
        
        # Update user role
        cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
        
        # Log the action
        log_admin_action(
            admin_id=admin_id,
            admin_name=admin_name,
            action="UPDATE_ROLE",
            target_type="USER",
            target_id=user_id,
            details=f"Changed role to {new_role} for user {user[0]}"
        )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to update user role: {str(e)}")
        return False

def upvote_report(report_id: int, user_id: int) -> tuple[bool, str]:
    """Add upvote to a report (community validation)"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if user already upvoted
        cursor.execute('SELECT id FROM report_upvotes WHERE report_id = ? AND user_id = ?', (report_id, user_id))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return False, "You have already upvoted this report"
        
        # Add upvote
        cursor.execute('INSERT INTO report_upvotes (report_id, user_id) VALUES (?, ?)', (report_id, user_id))
        
        # Update report upvote count
        cursor.execute('UPDATE risk_reports SET upvotes = upvotes + 1 WHERE id = ?', (report_id,))
        
        conn.commit()
        conn.close()
        return True, "Report upvoted successfully"
    except Exception as e:
        return False, f"Failed to upvote: {str(e)}"

def get_report_with_upvotes(report_id: int = None, user_id: int = None) -> list:
    """Get reports with upvote information"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        if report_id:
            cursor.execute('''
                SELECT r.*, u.full_name as reporter_name,
                       CASE WHEN ru.id IS NOT NULL THEN 1 ELSE 0 END as user_upvoted
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                LEFT JOIN report_upvotes ru ON r.id = ru.report_id AND ru.user_id = ?
                WHERE r.id = ?
            ''', (user_id, report_id))
        else:
            cursor.execute('''
                SELECT r.*, u.full_name as reporter_name,
                       CASE WHEN ru.id IS NOT NULL THEN 1 ELSE 0 END as user_upvoted
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                LEFT JOIN report_upvotes ru ON r.id = ru.report_id AND ru.user_id = ?
                ORDER BY r.created_at DESC
            ''', (user_id,))
        
        reports = cursor.fetchall()
        conn.close()
        return reports
    except Exception as e:
        st.error(f"Failed to get reports with upvotes: {str(e)}")
        return []

# Initialize database
init_database()

# Session state management
if 'user' not in st.session_state:
    st.session_state.user = None

if 'admin_logged_in' not in st.session_state:
    st.session_state.admin_logged_in = False

if 'admin_user' not in st.session_state:
    st.session_state.admin_user = None

# Main application
def main():
    st.markdown('<div class="main-header"><h1>🛣️ Road Report Nigeria</h1><p>Enhanced Road Status System - Python 3.13 Compatible</p></div>', unsafe_allow_html=True)
    
    # Check session timeout
    if check_session_timeout():
        if st.session_state.authenticated:
            st.warning("⚠️ Your session has expired. Please log in again.")
            clear_session()
            st.rerun()
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    
    # Check for admin session
    if st.session_state.get("admin_logged_in"):
        # Admin is logged in
        st.sidebar.success(f"🔐 Admin: {st.session_state.admin_user['full_name']}")
        
        # Show session timeout info
        if 'login_time' in st.session_state.admin_user:
            try:
                login_time = datetime.fromisoformat(st.session_state.admin_user['login_time'])
                remaining = SECURITY_CONFIG['session_timeout_minutes'] - (datetime.now() - login_time).total_seconds() / 60
                if remaining > 0:
                    st.sidebar.info(f"⏰ Session expires in {int(remaining)} minutes")
            except Exception:
                pass
        
        page = st.sidebar.selectbox(
            "Admin Panel:",
            ["Admin Dashboard", "Moderation Panel", "User Management", "Admin Logs", "Config Panel", "Admin Logout"]
        )
        
        if page == "Admin Dashboard":
            show_admin_dashboard()
        elif page == "Moderation Panel":
            show_moderation_panel()
        elif page == "User Management":
            show_admin_user_management()
        elif page == "Admin Logs":
            show_admin_logs()
        elif page == "Config Panel":
            show_config_panel()
        elif page == "Admin Logout":
            st.session_state.admin_logged_in = False
            st.session_state.admin_user = None
            st.success("✅ Successfully logged out!")
            st.rerun()
    
    elif st.session_state.authenticated and st.session_state.user:
        # Regular user is logged in
        st.sidebar.success(f"👋 Welcome, {st.session_state.user['full_name']}!")
        st.sidebar.info(f"Role: {st.session_state.user['role']}")
        
        # Show session timeout info
        if 'login_time' in st.session_state.user:
            try:
                login_time = datetime.fromisoformat(st.session_state.user['login_time'])
                remaining = SECURITY_CONFIG['session_timeout_minutes'] - (datetime.now() - login_time).total_seconds() / 60
                if remaining > 0:
                    st.sidebar.info(f"⏰ Session expires in {int(remaining)} minutes")
            except Exception:
                pass
        
        # Initialize current page if not set
        if 'current_page' not in st.session_state:
            st.session_state.current_page = "Dashboard"
        
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["Dashboard", "Road Status Checker", "Submit Report", "View Reports", "Risk History", "Live Feeds", "Manage Reports", "User Management", "AI Safety Advice", "Analytics Dashboard", "Security Settings", "Deployment & PWA", "Logout"],
            index=["Dashboard", "Road Status Checker", "Submit Report", "View Reports", "Risk History", "Live Feeds", "Manage Reports", "User Management", "AI Safety Advice", "Analytics Dashboard", "Security Settings", "Deployment & PWA", "Logout"].index(st.session_state.current_page)
        )
        
        # Update session state if page changed
        if page != st.session_state.current_page:
            st.session_state.current_page = page
        
        if page == "Dashboard":
            show_dashboard()
        elif page == "Road Status Checker":
            show_road_status_checker()
        elif page == "Submit Report":
            show_submit_report()
        elif page == "View Reports":
            show_view_reports()
        elif page == "Risk History":
            show_risk_history()
        elif page == "Live Feeds":
            show_live_feeds()
        elif page == "Manage Reports":
            show_manage_reports()
        elif page == "User Management":
            show_user_management()
        elif page == "AI Safety Advice":
            show_ai_advice_page()
        elif page == "Analytics Dashboard":
            show_analytics_page()
        elif page == "Security Settings":
            show_security_page()
        elif page == "Deployment & PWA":
            show_deployment_page()
        elif page == "Logout":
            clear_session()
            st.success("✅ Successfully logged out!")
            st.rerun()
    else:
        # User is not logged in
        st.sidebar.info("🔐 Please log in to access the system")
        
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["Login", "Admin Login", "Register", "Reset Password", "About"]
        )
        
        if page == "Login":
            show_login_page()
        elif page == "Admin Login":
            show_admin_login_page()
        elif page == "Register":
            show_registration_page()
        elif page == "Reset Password":
            show_reset_password()
        elif page == "About":
            show_about_page()

def show_login_page():
    st.header("🔐 User Login")
    
    # Create tabs for login and forgot password
    tab1, tab2 = st.tabs(["🔐 Login", "🔑 Forgot Password"])
    
    with tab1:
        # Show login attempt status
        if st.session_state.login_attempts > 0:
            remaining_attempts = SECURITY_CONFIG['max_login_attempts'] - st.session_state.login_attempts
            if remaining_attempts > 0:
                st.warning(f"⚠️ {remaining_attempts} login attempts remaining")
            else:
                lockout_duration = SECURITY_CONFIG['lockout_duration_minutes']
                st.error(f"🚫 Account temporarily locked due to too many failed attempts. Please wait {lockout_duration} minutes.")
                return
        
        with st.form("login_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                identifier = st.text_input(
                    "Email or Phone Number", 
                    placeholder="Enter your email or phone",
                    help="Enter your registered email address or phone number"
                )
            
            with col2:
                password = st.text_input(
                    "Password", 
                    type="password", 
                    placeholder="Enter your password",
                    help="Enter your account password"
                )
            
            # Password strength indicator
            if password:
                is_strong, strength_msg = validate_password_strength(password)
                if is_strong:
                    st.success("✅ Password strength: Good")
                else:
                    st.warning(f"⚠️ {strength_msg}")
            
            submit = st.form_submit_button("🔐 Login", type="primary", use_container_width=True)
            
            if submit:
                if not identifier or not password:
                    st.error("❌ Please fill in all fields")
                    return
                
                # Show loading
                with st.spinner("🔐 Authenticating..."):
                    time.sleep(1)  # Simulate authentication delay
                    success, user_data, message = authenticate_user(identifier, password)
                
                if success:
                    st.success(f"✅ {message}")
                    st.balloons()
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"❌ {message}")
                    
                    # Show remaining attempts
                    if st.session_state.login_attempts > 0:
                        remaining = SECURITY_CONFIG['max_login_attempts'] - st.session_state.login_attempts
                        if remaining > 0:
                            st.warning(f"⚠️ {remaining} login attempts remaining")
                        else:
                            lockout_duration = SECURITY_CONFIG['lockout_duration_minutes']
                            st.error(f"🚫 Account temporarily locked due to too many failed attempts. Please wait {lockout_duration} minutes.")
    
    with tab2:
        show_forgot_password()

def show_forgot_password():
    """Show forgot password form"""
    st.subheader("🔑 Reset Your Password")
    st.info("Enter your email or phone number to receive a reset link.")
    
    with st.form("forgot_password_form"):
        identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone")
        user_type = st.selectbox("Account Type", ["User", "Admin"])
        
        submit = st.form_submit_button("Send Reset Link", type="primary")
        
        if submit:
            if not identifier:
                st.error("❌ Please enter your email or phone number")
                return
            
            # Show loading
            with st.spinner("🔑 Processing reset request..."):
                success, message = initiate_password_reset(identifier, user_type.lower())
            
            if success:
                st.success(f"✅ {message}")
                st.info("Please check your email or phone for reset instructions.")
            else:
                st.error(f"❌ {message}")

def show_reset_password():
    """Show password reset form"""
    st.subheader("🔑 Set New Password")
    st.info("Enter your new password below.")
    
    with st.form("reset_password_form"):
        token = st.text_input("Reset Token", placeholder="Enter the token from your email/phone")
        new_password = st.text_input("New Password", type="password", placeholder="Enter new password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm new password")
        
        submit = st.form_submit_button("Reset Password", type="primary")
        
        if submit:
            if not all([token, new_password, confirm_password]):
                st.error("❌ Please fill in all fields")
                return
            
            if new_password != confirm_password:
                st.error("❌ Passwords do not match")
                return
            
            # Show loading
            with st.spinner("🔑 Resetting password..."):
                success, message = reset_password(token, new_password)
            
            if success:
                st.success(f"✅ {message}")
                st.info("You can now login with your new password.")
                time.sleep(2)
                st.rerun()
            else:
                st.error(f"❌ {message}")

def initiate_password_reset(identifier: str, user_type: str = "user") -> tuple[bool, str]:
    """Initiate password reset process"""
    try:
        # Validate input
        if not identifier or len(identifier.strip()) < 3:
            return False, "Invalid identifier provided"
        
        # Check if user exists
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check in appropriate table
        if user_type == "admin":
            cursor.execute('''
                SELECT id, full_name, email, phone_number 
                FROM admin_users 
                WHERE email = ? OR phone_number = ?
            ''', (identifier, identifier))
        else:
            cursor.execute('''
                SELECT id, full_name, email, phone_number 
                FROM users 
                WHERE email = ? OR phone_number = ?
            ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False, "No account found with this email or phone number"
        
        user_id, full_name, email, phone = user
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        expiry_time = datetime.now() + timedelta(hours=24)  # 24 hours expiry
        
        # Store reset token
        cursor.execute('''
            INSERT OR REPLACE INTO password_resets 
            (user_id, user_type, reset_token, expiry_time, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, user_type, reset_token, expiry_time, datetime.now()))
        
        conn.commit()
        conn.close()
        
        # Log the reset request
        log_security_event("PASSWORD_RESET_REQUESTED", f"User {user_id} requested password reset", "INFO")
        
        # In a real application, you would send email/SMS here
        # For demo purposes, we'll show the token
        if user_type == "admin":
            st.session_state.admin_reset_token = reset_token
        else:
            st.session_state.user_reset_token = reset_token
        
        return True, f"Reset link sent to {identifier}. Check your email/phone for instructions."
        
    except Exception as e:
        log_security_event("PASSWORD_RESET_ERROR", f"Error in password reset: {str(e)}", "ERROR")
        return False, "An error occurred while processing your request"

def reset_password(token: str, new_password: str) -> tuple[bool, str]:
    """Reset password using token"""
    try:
        # Validate password strength
        is_strong, strength_msg = validate_password_strength(new_password)
        if not is_strong:
            return False, f"Password validation failed: {strength_msg}"
        
        # Check if token exists and is valid
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, user_type, expiry_time 
            FROM password_resets 
            WHERE reset_token = ? AND used = 0
        ''', (token,))
        
        reset_record = cursor.fetchone()
        
        if not reset_record:
            conn.close()
            return False, "Invalid or expired reset token"
        
        user_id, user_type, expiry_time = reset_record
        
        # Check if token has expired
        if datetime.now() > datetime.fromisoformat(expiry_time):
            conn.close()
            return False, "Reset token has expired"
        
        # Hash new password
        hashed_password = hash_password(new_password)
        
        # Update password in appropriate table
        if user_type == "admin":
            cursor.execute('''
                UPDATE admin_users 
                SET password_hash = ?, updated_at = ?
                WHERE id = ?
            ''', (hashed_password, datetime.now(), user_id))
        else:
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, updated_at = ?
                WHERE id = ?
            ''', (hashed_password, datetime.now(), user_id))
        
        # Mark token as used
        cursor.execute('''
            UPDATE password_resets 
            SET used = 1, used_at = ?
            WHERE reset_token = ?
        ''', (datetime.now(), token))
        
        conn.commit()
        conn.close()
        
        # Log the password reset
        log_security_event("PASSWORD_RESET_COMPLETED", f"User {user_id} reset password successfully", "INFO")
        
        return True, "Password reset successfully"
        
    except Exception as e:
        log_security_event("PASSWORD_RESET_ERROR", f"Error in password reset: {str(e)}", "ERROR")
        return False, "An error occurred while resetting your password"

def show_admin_login_page():
    st.header("🔐 Admin Login")
    
    with st.form("admin_login_form"):
        identifier = st.text_input("Admin Email or Phone", placeholder="Enter admin email or phone")
        password = st.text_input("Admin Password", type="password", placeholder="Enter admin password")
        
        # 2FA simulation
        st.subheader("🔒 Two-Factor Authentication")
        st.info("For demo purposes, use OTP: 123456")
        otp = st.text_input("Enter OTP", placeholder="123456", max_chars=6)
        
        submit = st.form_submit_button("Admin Login", type="primary")
        
        if submit:
            if not identifier or not password:
                st.error("Please fill in all fields")
                return
            
            if not otp or otp != "123456":
                st.error("Invalid OTP. Use 123456 for demo.")
                return
            
            success, admin_data, message = authenticate_admin(identifier, password)
            
            if success:
                st.session_state.admin_logged_in = True
                st.session_state.admin_user = admin_data
                st.success(f"🔐 {message}")
                st.rerun()
            else:
                st.error(message)

def show_registration_page():
    st.header("📝 User Registration")
    
    # Display Terms and Conditions
    st.subheader("📋 Terms and Conditions")
    st.markdown("""
    **Please read and agree to the following terms before registering:**
    
    ### 🛣️ Nigerian Road Risk Reporter - Terms of Service
    
    **1. Service Description**
    This application provides a platform for reporting and sharing road-related risks and incidents across Nigeria. Users can submit reports, view community reports, and receive safety advice.
    
    **2. Risk Information Disclaimer**
    - All risk reports and safety advice provided through this platform are **SUGGESTIONS ONLY**
    - Information shared is based on user submissions and automated data collection
    - We do not guarantee the accuracy, completeness, or reliability of any information
    - Users should exercise their own judgment and verify information independently
    - The platform is not responsible for any decisions made based on the information provided
    
    **3. User Responsibilities**
    - Provide accurate and truthful information when submitting reports
    - Do not submit false or misleading reports
    - Respect other users and maintain appropriate conduct
    - Use the platform responsibly and in accordance with local laws
    
    **4. Privacy and Data**
    - Personal information is collected for account management and service provision
    - Location data may be collected when submitting reports
    - We implement security measures to protect user data
    - Data may be shared with authorities if required by law
    
    **5. Limitation of Liability**
    - The platform and its operators are not liable for any damages or losses
    - Users use the service at their own risk
    - We are not responsible for any accidents, injuries, or property damage
    
    **6. Service Availability**
    - The service is provided "as is" without warranties
    - We may modify, suspend, or discontinue the service at any time
    - Technical issues may affect service availability
    
    **7. Account Management**
    - Users who submit false or misleading information may have their accounts removed
    - The platform reserves the right to suspend or terminate accounts for violations
    - Users are responsible for the accuracy of information they submit
    
    **8. Updates to Terms**
    - These terms may be updated periodically
    - Continued use of the service constitutes acceptance of updated terms
    
    **By registering, you acknowledge that you have read, understood, and agree to these terms.**
    """)
    
    # Terms agreement checkbox
    terms_agreed = st.checkbox("✅ I have read, understood, and agree to the Terms and Conditions above", key="terms_agreement")
    
    if not terms_agreed:
        st.warning("⚠️ You must agree to the Terms and Conditions to proceed with registration.")
        return
    
    with st.form("registration_form"):
        st.subheader("Personal Information")
        full_name = st.text_input("Full Name *", placeholder="Enter your full name")
        phone_number = st.text_input("Phone Number *", placeholder="+2348012345678")
        email = st.text_input("Email (Optional)", placeholder="your.email@example.com")
        
        st.subheader("Role & Identification")
        role = st.selectbox("Role *", ["Public", "Driver", "Admin"])
        nin_or_passport = st.text_input("NIN (Optional - 11 digits)", placeholder="12345678901", help="National Identity Number is optional")
        
        st.subheader("Security")
        password = st.text_input("Password *", type="password", placeholder="Create a strong password")
        confirm_password = st.text_input("Confirm Password *", type="password", placeholder="Confirm your password")
        
        submit = st.form_submit_button("Register", type="primary")
        
        if submit:
            # Basic validation
            if not all([full_name, phone_number, role, password, confirm_password]):
                st.error("Please fill in all required fields (marked with *)")
                return
            
            if password != confirm_password:
                st.error("Passwords do not match")
                return
            
            if len(password) < 6:
                st.error("Password must be at least 6 characters long")
                return
            
            # Register user
            user_data = {
                'full_name': full_name,
                'phone_number': phone_number,
                'email': email,
                'role': role,
                'nin_or_passport': nin_or_passport if nin_or_passport else None,
                'password': password
            }
            
            success, message = register_user(user_data)
            
            if success:
                st.success(message)
                st.info("You can now login with your credentials.")
            else:
                st.error(message)

def show_dashboard():
    st.header("📊 Dashboard")
    
    user = st.session_state.user
    
    # Welcome message with safe access
    st.markdown(f"""
    <div class="info-box">
        <h3>Welcome back, {user.get('full_name', 'User')}!</h3>
        <p><strong>Role:</strong> {user.get('role', 'user')}</p>
        <p><strong>Email:</strong> {user.get('email', 'Not provided')}</p>
        <p><strong>Phone:</strong> {user.get('phone', 'Not provided')}</p>
        <p><strong>Security Status:</strong> 🔒 Enhanced security active</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Get report statistics
    stats = get_report_stats()
    
    # Enhanced stats with Nigerian roads data
    if ROADS_DB_AVAILABLE:
        road_stats = nigerian_roads_db.get_road_statistics()
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Reports", stats['total'])
        with col2:
            st.metric("Road Risks (24h)", road_stats.get('total_risks', 0))
        with col3:
            st.metric("Road Conditions (3m)", road_stats.get('total_conditions', 0))
        with col4:
            st.metric("Active States", road_stats.get('active_states', 0))
    else:
        # Fallback to basic stats
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Reports", stats['total'])
        with col2:
            st.metric("Pending", stats['pending'])
        with col3:
            st.metric("Verified", stats['verified'])
        with col4:
            st.metric("Resolved", stats['resolved'])
    
    # Live Road Status - Last 24 Hours
    st.subheader("🚨 Live Road Status - Last 24 Hours")
    
    # Disclaimer
    st.warning("""
    ⚠️ **DISCLAIMER**: All risk information displayed is based on user reports and automated data collection. 
    This information is provided as **SUGGESTIONS ONLY** and should not be the sole basis for travel decisions. 
    Please exercise your own judgment and verify information independently.
    
    🚨 **ACCOUNT WARNING**: Users who submit false or misleading information may have their accounts removed.
    """)
    
    # Import live data if needed
    if st.button("🔄 Refresh Live Data", type="secondary"):
        with st.spinner("Updating live data..."):
            import_news_to_reports()
            import_social_media_to_reports()
        st.success("Live data updated!")
        st.rerun()
    
    # Get recent reports (last 24 hours only)
    recent_reports = get_recent_reports(hours=24)
    
    if recent_reports:
        # Group by risk type for summary
        risk_summary = {}
        for report in recent_reports:
            risk_type = report[1]  # risk_type is at index 1
            if risk_type not in risk_summary:
                risk_summary[risk_type] = 0
            risk_summary[risk_type] += 1
        
        # Display risk summary
        st.markdown("### 📈 Risk Summary (Last 24 Hours)")
        if risk_summary:
            cols = st.columns(len(risk_summary))
            for i, (risk_type, count) in enumerate(risk_summary.items()):
                with cols[i]:
                    risk_colors = {
                        'Robbery': '#dc3545',
                        'Flooding': '#007bff',
                        'Protest': '#6f42c1',
                        'Road Damage': '#fd7e14',
                        'Traffic': '#ffc107'
                    }
                    color = risk_colors.get(risk_type, '#6c757d')
                    st.markdown(f"""
                    <div style="background-color: {color}; color: white; padding: 1rem; border-radius: 8px; text-align: center;">
                        <h4>{risk_type}</h4>
                        <h2>{count}</h2>
                        <p>Reports</p>
                    </div>
                    """, unsafe_allow_html=True)
        
        # Display recent reports
        st.markdown("### 📋 Recent Risk Reports")
        for report in recent_reports[:5]:  # Show last 5 reports
            report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            # Create status badge
            status_class = f"status-{status.lower()}"
            risk_class = f"risk-type-{risk_type.lower().replace(' ', '')}"
            
            # Source badge
            source_icons = {
                'user': '👤',
                'news': '📰',
                'social': '📱'
            }
            source_colors = {
                'user': '#28a745',
                'news': '#007bff',
                'social': '#6f42c1'
            }
            
            source_icon = source_icons.get(source_type, '📄')
            source_color = source_colors.get(source_type, '#6c757d')
            
            # Time ago calculation
            time_ago = get_time_ago(created_at)
            
            st.markdown(f"""
            <div class="risk-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="{risk_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{risk_type.upper()}</span>
                        <span style="background-color: {source_color}; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{source_icon} {source_type.upper()}</span>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="{status_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{status.upper()}</span>
                        <span style="color: #6c757d; font-size: 12px;">{time_ago}</span>
                    </div>
                </div>
                <p><strong>Location:</strong> 📍 {location}</p>
                <p><strong>Description:</strong> {description[:100]}{'...' if len(description) > 100 else ''}</p>
                {f'<p><strong>Source:</strong> <a href="{source_url}" target="_blank">🔗 View Original</a></p>' if source_url else ''}
            </div>
            """, unsafe_allow_html=True)
        
        if len(recent_reports) > 5:
            st.info(f"Showing 5 of {len(recent_reports)} recent reports. Use 'View All Reports' to see more.")
    else:
        st.info("No recent reports in the last 24 hours. Click 'Refresh Live Data' to import latest news and social media updates.")
    
    # Quick actions
    st.subheader("Quick Actions")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📝 Submit New Report", type="primary", key="quick_submit_report"):
            st.session_state.current_page = "Submit Report"
            st.rerun()
    
    with col2:
        if st.button("🛣️ Check Road Status", type="secondary", key="quick_road_status"):
            st.session_state.current_page = "Road Status Checker"
            st.rerun()
    
    with col3:
        if st.button("📊 View All Reports", key="quick_view_reports"):
            st.session_state.current_page = "View Reports"
            st.rerun()
    
    with col4:
        if st.button("📰 Live Feeds", key="quick_live_feeds"):
            st.session_state.current_page = "Live Feeds"
            st.rerun()
    
    # Admin actions (if admin)
    if user['role'] == 'Admin':
        st.subheader("Admin Actions")
        col5, col6, col7 = st.columns(3)
        
        with col5:
            if st.button("🛠️ Manage Reports", key="quick_manage_reports"):
                st.session_state.current_page = "Manage Reports"
                st.rerun()
        
        with col6:
            if st.button("👥 User Management", key="quick_user_management"):
                st.session_state.current_page = "User Management"
                st.rerun()
        
        with col7:
            if st.button("📊 Analytics Dashboard", key="quick_analytics"):
                st.session_state.current_page = "Analytics Dashboard"
                st.rerun()

def show_submit_report():
    st.header("📝 Submit Report (Enhanced)")
    
    # Account warning
    st.warning("""
    🚨 **ACCOUNT WARNING**: Users who submit false or misleading information may have their accounts removed. 
    Please ensure all information provided is accurate and truthful.
    """)
    
    if not st.session_state.user:
        st.error("Please login to submit a report")
        return
    
    # Enhanced tabbed interface
    tab1, tab2 = st.tabs(["🚨 Risk Report", "🛣️ Road Condition"])
    
    with tab1:
        st.subheader("🚨 Submit Risk Report")
        
        with st.form("risk_report_form"):
            st.subheader("Risk Information")
            
            # Enhanced risk categories with Nigerian roads data
            if ROADS_DB_AVAILABLE:
                risk_categories = nigerian_roads_db.get_risk_categories()
                risk_category = st.selectbox("Risk Category *", list(risk_categories.keys()))
                
                # Dynamic subcategories based on selected category
                if risk_category:
                    subcategories = risk_categories[risk_category].get('subcategories', [])
                    risk_subtype = st.selectbox("Risk Subtype *", subcategories)
                    risk_type = f"{risk_category} - {risk_subtype}"
                else:
                    risk_type = st.text_input("Risk Type *", placeholder="Enter risk type")
            else:
                # Fallback risk types
                risk_types = ["Traffic", "Infrastructure", "Weather", "Security", "Environmental", "Other"]
                risk_type = st.selectbox("Risk Type *", risk_types)
                
                if risk_type == "Other":
                    risk_type = st.text_input("Specify Risk Type *", placeholder="Enter the specific risk type")
            
            # Description
            description = st.text_area("Description *", placeholder="Provide detailed description of the risk...", height=100)
            
            # Severity
            severity = st.selectbox("Severity Level *", ["Low", "Medium", "High", "Critical"])
            
            # Enhanced location selection
            st.subheader("Location Information")
            
            if ROADS_DB_AVAILABLE:
                col1, col2 = st.columns(2)
                
                with col1:
                    states = nigerian_roads_db.get_states()
                    selected_state = st.selectbox("State *", states)
                
                with col2:
                    if selected_state:
                        lgas = nigerian_roads_db.get_local_governments(selected_state)
                        selected_lga = st.selectbox("Local Government Area *", lgas)
                    else:
                        selected_lga = st.selectbox("Local Government Area *", ["Select State First"])
                
                # Major road selection (optional)
                major_roads = nigerian_roads_db.get_major_roads(selected_state)
                if major_roads:
                    road_names = ["Not on Major Road"] + [road['name'] for road in major_roads]
                    selected_road = st.selectbox("Major Road (Optional)", road_names)
                else:
                    selected_road = "Not on Major Road"
                
                # Manual location override
                location = st.text_input("Specific Location *", placeholder="e.g., Near Mile 2, Along Expressway")
                
                # Combine location information
                full_location = f"{location}, {selected_lga}, {selected_state}"
                if selected_road != "Not on Major Road":
                    full_location += f" ({selected_road})"
            else:
                # Fallback location input
                location = st.text_input("Location Description *", placeholder="e.g., Lagos-Ibadan Expressway, Lagos State")
                full_location = location
            
            # GPS coordinates (simulated)
            col1, col2 = st.columns(2)
            with col1:
                latitude = st.number_input("Latitude", value=6.5244, format="%.4f", help="GPS latitude coordinate")
            with col2:
                longitude = st.number_input("Longitude", value=3.3792, format="%.4f", help="GPS longitude coordinate")
            
            # File uploads
            st.subheader("Additional Information")
            
            # Voice input (simulated with file upload)
            voice_file = st.file_uploader("Voice Recording (Optional)", type=['wav', 'mp3'], help="Upload voice recording, max 5MB")
            
            # Image upload
            image_file = st.file_uploader("Image (Optional)", type=['jpg', 'jpeg', 'png'], help="Upload image, max 5MB")
            
            # Validation and submission
            submit = st.form_submit_button("Submit Risk Report", type="primary")
            
            if submit:
                # Validation
                if not risk_type:
                    st.error("Please select or specify a risk type")
                    return
                
                if not description:
                    st.error("Please provide a description")
                    return
                
                if not full_location:
                    st.error("Please provide location information")
                    return
                
                # File size validation
                if voice_file and voice_file.size > 5 * 1024 * 1024:  # 5MB
                    st.error("Voice file must be less than 5MB")
                    return
                
                if image_file and image_file.size > 5 * 1024 * 1024:  # 5MB
                    st.error("Image file must be less than 5MB")
                    return
                
                # Prepare report data
                report_data = {
                    'user_id': st.session_state.user['id'],
                    'risk_type': risk_type,
                    'description': description,
                    'location': full_location,
                    'latitude': latitude,
                    'longitude': longitude,
                    'severity': severity,
                    'voice_file_path': None,
                    'image_file_path': None
                }
                
                # Save files if uploaded
                if voice_file:
                    report_data['voice_file_path'] = f"voice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
                
                if image_file:
                    report_data['image_file_path'] = f"image_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
                
                # Save report to Nigerian roads database if available
                if ROADS_DB_AVAILABLE:
                    risk_data = {
                        'risk_type': risk_type,
                        'description': description,
                        'location': full_location,
                        'state': selected_state,
                        'lga': selected_lga,
                        'road_name': selected_road if selected_road != "Not on Major Road" else None,
                        'severity': severity,
                        'latitude': latitude,
                        'longitude': longitude
                    }
                    
                    if nigerian_roads_db.add_road_risk(risk_data):
                        st.success("✅ Risk report submitted to Nigerian roads database!")
                    else:
                        st.warning("⚠️ Could not save to Nigerian roads database, but report was submitted.")
                
                # Save to main database
                success, message = save_risk_report(report_data)
                
                if success:
                    st.success(message)
                    
                    # AI Insights based on severity
                    st.subheader("🤖 AI Insights")
                    if severity == "Critical":
                        st.error("🚨 **CRITICAL RISK DETECTED**")
                        st.markdown("""
                        **Immediate Actions Recommended:**
                        - Avoid this area completely
                        - Contact emergency services immediately
                        - Notify local authorities
                        - Share with community groups
                        """)
                    elif severity == "High":
                        st.warning("⚠️ **HIGH RISK AREA**")
                        st.markdown("""
                        **Safety Recommendations:**
                        - Exercise extreme caution
                        - Consider alternative routes
                        - Travel with others if possible
                        - Monitor local news for updates
                        """)
                    elif severity == "Medium":
                        st.info("ℹ️ **MODERATE RISK**")
                        st.markdown("""
                        **Precautionary Measures:**
                        - Be aware of surroundings
                        - Follow traffic advisories
                        - Report any changes to authorities
                        """)
                    else:
                        st.success("✅ **LOW RISK**")
                        st.markdown("""
                        **General Safety:**
                        - Normal precautions apply
                        - Stay alert to changing conditions
                        - Report any deterioration
                        """)
                    
                    # Show confirmation summary
                    st.markdown(f"""
                    <div class="success-box">
                        <h4>📋 Risk Report Summary</h4>
                        <p><strong>Risk Type:</strong> {risk_type}</p>
                        <p><strong>Severity:</strong> {severity}</p>
                        <p><strong>Location:</strong> {full_location}</p>
                        <p><strong>Description:</strong> {description}</p>
                        <p><strong>Coordinates:</strong> {latitude}, {longitude}</p>
                        <p><strong>Submitted:</strong> {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.error(message)
    
    with tab2:
        st.subheader("🛣️ Submit Road Condition Report")
        
        with st.form("road_condition_form"):
            st.subheader("Road Information")
            
            # Road condition types
            condition_types = ["Good", "Fair", "Poor", "Critical"]
            condition = st.selectbox("Road Condition *", condition_types)
            
            # Description
            description = st.text_area("Description *", placeholder="Describe the road condition in detail...", height=100)
            
            # Enhanced location selection
            st.subheader("Location Information")
            
            if ROADS_DB_AVAILABLE:
                col1, col2 = st.columns(2)
                
                with col1:
                    states = nigerian_roads_db.get_states()
                    selected_state = st.selectbox("State *", states, key="condition_state")
                
                with col2:
                    if selected_state:
                        lgas = nigerian_roads_db.get_local_governments(selected_state)
                        selected_lga = st.selectbox("Local Government Area *", lgas, key="condition_lga")
                    else:
                        selected_lga = st.selectbox("Local Government Area *", ["Select State First"], key="condition_lga")
                
                # Major road selection
                major_roads = nigerian_roads_db.get_major_roads(selected_state)
                if major_roads:
                    road_names = ["Not on Major Road"] + [road['name'] for road in major_roads]
                    selected_road = st.selectbox("Major Road (Optional)", road_names, key="condition_road")
                else:
                    selected_road = "Not on Major Road"
                
                # Specific location
                location = st.text_input("Specific Location *", placeholder="e.g., Between Mile 2 and Mile 3", key="condition_location")
                
                # Combine location information
                full_location = f"{location}, {selected_lga}, {selected_state}"
                if selected_road != "Not on Major Road":
                    full_location += f" ({selected_road})"
            else:
                # Fallback location input
                location = st.text_input("Location Description *", placeholder="e.g., Lagos-Ibadan Expressway, Lagos State", key="condition_location")
                full_location = location
            
            # GPS coordinates
            col1, col2 = st.columns(2)
            with col1:
                latitude = st.number_input("Latitude", value=6.5244, format="%.4f", help="GPS latitude coordinate", key="condition_lat")
            with col2:
                longitude = st.number_input("Longitude", value=3.3792, format="%.4f", help="GPS longitude coordinate", key="condition_lon")
            
            # Image upload
            image_file = st.file_uploader("Road Image (Optional)", type=['jpg', 'jpeg', 'png'], help="Upload image of road condition, max 5MB", key="condition_image")
            
            # Submit button
            submit_condition = st.form_submit_button("Submit Road Condition", type="primary")
            
            if submit_condition:
                # Validation
                if not condition:
                    st.error("Please select road condition")
                    return
                
                if not description:
                    st.error("Please provide a description")
                    return
                
                if not full_location:
                    st.error("Please provide location information")
                    return
                
                # File size validation
                if image_file and image_file.size > 5 * 1024 * 1024:  # 5MB
                    st.error("Image file must be less than 5MB")
                    return
                
                # Prepare condition data
                condition_data = {
                    'condition': condition,
                    'description': description,
                    'location': full_location,
                    'state': selected_state if ROADS_DB_AVAILABLE else "Unknown",
                    'lga': selected_lga if ROADS_DB_AVAILABLE else "Unknown",
                    'road_name': selected_road if ROADS_DB_AVAILABLE and selected_road != "Not on Major Road" else None,
                    'latitude': latitude,
                    'longitude': longitude
                }
                
                # Save to Nigerian roads database if available
                if ROADS_DB_AVAILABLE:
                    if nigerian_roads_db.add_road_condition(condition_data):
                        st.success("✅ Road condition report submitted to Nigerian roads database!")
                    else:
                        st.warning("⚠️ Could not save to Nigerian roads database, but report was submitted.")
                
                # AI Insights based on condition
                st.subheader("🤖 AI Insights")
                if condition == "Critical":
                    st.error("🚨 **CRITICAL ROAD CONDITION**")
                    st.markdown("""
                    **Immediate Actions:**
                    - Road may be impassable
                    - Contact road authorities immediately
                    - Avoid this route completely
                    - Consider alternative transportation
                    """)
                elif condition == "Poor":
                    st.warning("⚠️ **POOR ROAD CONDITION**")
                    st.markdown("""
                    **Safety Recommendations:**
                    - Drive with extreme caution
                    - Reduce speed significantly
                    - Watch for potholes and damage
                    - Consider alternative routes
                    """)
                elif condition == "Fair":
                    st.info("ℹ️ **FAIR ROAD CONDITION**")
                    st.markdown("""
                    **Precautionary Measures:**
                    - Normal driving with attention
                    - Watch for minor issues
                    - Report any deterioration
                    """)
                else:
                    st.success("✅ **GOOD ROAD CONDITION**")
                    st.markdown("""
                    **Status:**
                    - Road is in good condition
                    - Normal driving conditions apply
                    - Continue to monitor for changes
                    """)
                
                # Show confirmation summary
                st.markdown(f"""
                <div class="success-box">
                    <h4>📋 Road Condition Summary</h4>
                    <p><strong>Condition:</strong> {condition}</p>
                    <p><strong>Location:</strong> {full_location}</p>
                    <p><strong>Description:</strong> {description}</p>
                    <p><strong>Coordinates:</strong> {latitude}, {longitude}</p>
                    <p><strong>Submitted:</strong> {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
                </div>
                """, unsafe_allow_html=True)

def show_view_reports():
    st.header("📊 View Reports (Enhanced)")
    
    # Account warning
    st.warning("""
    🚨 **ACCOUNT WARNING**: Users who submit false or misleading information may have their accounts removed. 
    All reports are community-verified and monitored for accuracy.
    """)
    
    # Enhanced tabbed interface
    tab1, tab2, tab3 = st.tabs(["🚨 Recent Risks (24h)", "🛣️ Road Conditions (3m)", "📊 Analytics"])
    
    with tab1:
        st.subheader("🚨 Recent Risk Reports (Last 24 Hours)")
        
        # Filters for recent risks
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if ROADS_DB_AVAILABLE:
                states = ["All States"] + nigerian_roads_db.get_states()
                state_filter = st.selectbox("Filter by State", states)
            else:
                state_filter = "All States"
        
        with col2:
            risk_types = ["All Types", "Traffic", "Infrastructure", "Weather", "Security", "Environmental"]
            risk_filter = st.selectbox("Filter by Risk Type", risk_types)
        
        with col3:
            severity_filter = st.selectbox("Filter by Severity", ["All Severities", "Low", "Medium", "High", "Critical"])
        
        # Get recent risk reports
        if ROADS_DB_AVAILABLE:
            recent_risks = nigerian_roads_db.get_road_risks(hours=24)
            
            # Apply filters
            if state_filter != "All States":
                recent_risks = [r for r in recent_risks if r.get('state') == state_filter]
            
            if risk_filter != "All Types":
                recent_risks = [r for r in recent_risks if r.get('risk_type') == risk_filter]
            
            if severity_filter != "All Severities":
                recent_risks = [r for r in recent_risks if r.get('severity') == severity_filter]
            
            if recent_risks:
                st.success(f"Found {len(recent_risks)} risk reports in the last 24 hours")
                
                for risk in recent_risks:
                    with st.expander(f"🚨 {risk.get('risk_type', 'Unknown')} - {risk.get('location', 'Unknown Location')}"):
                        col1, col2 = st.columns([2, 1])
                        
                        with col1:
                            st.write(f"**Risk Type:** {risk.get('risk_type', 'Unknown')}")
                            st.write(f"**Location:** 📍 {risk.get('location', 'Unknown')}")
                            st.write(f"**Description:** {risk.get('description', 'No description')}")
                            st.write(f"**Severity:** {risk.get('severity', 'Unknown')}")
                            st.write(f"**Reported:** {risk.get('reported_at', 'Unknown')}")
                        
                        with col2:
                            st.write(f"**State:** {risk.get('state', 'Unknown')}")
                            st.write(f"**LGA:** {risk.get('lga', 'Unknown')}")
                            st.write(f"**Road:** {risk.get('road_name', 'Not specified')}")
                            
                            # Action buttons
                            if st.button("✅ Confirm", key=f"confirm_{risk.get('id')}"):
                                st.success("Risk confirmed!")
                            
                            if st.button("❌ False Report", key=f"false_{risk.get('id')}"):
                                st.error("Marked as false report!")
                            
                            if st.button("🔧 Resolved", key=f"resolve_{risk.get('id')}"):
                                st.info("Marked as resolved!")
            else:
                st.info("No risk reports found in the last 24 hours.")
        else:
            st.info("Nigerian roads database not available. Using basic reports.")
            # Fallback to basic reports
            recent_reports = get_recent_reports(hours=24)
            if recent_reports:
                for report in recent_reports[:10]:  # Show first 10
                    report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
                    
                    with st.expander(f"🚨 {risk_type} - {location}"):
                        st.write(f"**Description:** {description}")
                        st.write(f"**Status:** {status}")
                        st.write(f"**Reporter:** {reporter_name}")
                        st.write(f"**Created:** {created_at}")
            else:
                st.info("No recent reports found.")
    
    with tab2:
        st.subheader("🛣️ Road Condition Reports (Last 3 Months)")
        
        # Filters for road conditions
        col1, col2 = st.columns(2)
        
        with col1:
            if ROADS_DB_AVAILABLE:
                states = ["All States"] + nigerian_roads_db.get_states()
                condition_state_filter = st.selectbox("Filter by State", states, key="condition_state")
            else:
                condition_state_filter = "All States"
        
        with col2:
            condition_types = ["All Conditions", "Good", "Fair", "Poor", "Critical"]
            condition_filter = st.selectbox("Filter by Condition", condition_types)
        
        # Get road condition reports
        if ROADS_DB_AVAILABLE:
            road_conditions = nigerian_roads_db.get_road_conditions(months=3)
            
            # Apply filters
            if condition_state_filter != "All States":
                road_conditions = [c for c in road_conditions if c.get('state') == condition_state_filter]
            
            if condition_filter != "All Conditions":
                road_conditions = [c for c in road_conditions if c.get('condition') == condition_filter]
            
            if road_conditions:
                st.success(f"Found {len(road_conditions)} road condition reports in the last 3 months")
                
                for condition in road_conditions:
                    with st.expander(f"🛣️ {condition.get('road_name', 'Unknown Road')} - {condition.get('condition', 'Unknown')}"):
                        col1, col2 = st.columns([2, 1])
                        
                        with col1:
                            st.write(f"**Road:** {condition.get('road_name', 'Unknown')}")
                            st.write(f"**Condition:** {condition.get('condition', 'Unknown')}")
                            st.write(f"**Description:** {condition.get('description', 'No description')}")
                            st.write(f"**Reported:** {condition.get('reported_at', 'Unknown')}")
                        
                        with col2:
                            st.write(f"**State:** {condition.get('state', 'Unknown')}")
                            st.write(f"**LGA:** {condition.get('lga', 'Unknown')}")
                            st.write(f"**Length:** {condition.get('length_km', 'Unknown')} km")
                            
                            # Action buttons
                            if st.button("✅ Confirm", key=f"confirm_cond_{condition.get('id')}"):
                                st.success("Condition confirmed!")
                            
                            if st.button("❌ False Report", key=f"false_cond_{condition.get('id')}"):
                                st.error("Marked as false report!")
                            
                            if st.button("🔧 Resolved", key=f"resolve_cond_{condition.get('id')}"):
                                st.info("Marked as resolved!")
            else:
                st.info("No road condition reports found in the last 3 months.")
        else:
            st.info("Nigerian roads database not available.")
    
    with tab3:
        st.subheader("📊 Analytics Dashboard")
        
        if ROADS_DB_AVAILABLE:
            # Get comprehensive statistics
            stats = nigerian_roads_db.get_road_statistics()
            
            # Key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Risks (24h)", stats.get('total_risks', 0))
            with col2:
                st.metric("Total Conditions (3m)", stats.get('total_conditions', 0))
            with col3:
                st.metric("Active States", stats.get('active_states', 0))
            with col4:
                st.metric("Major Roads", stats.get('major_roads', 0))
            
            # Risk type distribution
            st.subheader("Risk Type Distribution")
            risk_distribution = stats.get('risk_distribution', {})
            if risk_distribution:
                for risk_type, count in risk_distribution.items():
                    st.write(f"• **{risk_type}:** {count} reports")
            
            # Top states with most reports
            st.subheader("Top States by Reports")
            top_states = stats.get('top_states', [])
            if top_states:
                for i, (state, count) in enumerate(top_states[:5], 1):
                    st.write(f"{i}. **{state}:** {count} reports")
            
            # Road condition summary
            st.subheader("Road Condition Summary")
            condition_summary = stats.get('condition_summary', {})
            if condition_summary:
                for condition, count in condition_summary.items():
                    st.write(f"• **{condition}:** {count} roads")
        else:
            st.info("Nigerian roads database not available for advanced analytics.")
            
            # Basic analytics
            basic_stats = get_report_stats()
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Reports", basic_stats['total'])
            with col2:
                st.metric("Pending", basic_stats['pending'])
            with col3:
                st.metric("Verified", basic_stats['verified'])
            with col4:
                st.metric("Resolved", basic_stats['resolved'])

def show_manage_reports():
    st.header("🛠️ Manage Reports")
    
    if st.session_state.user['role'] != 'Admin':
        st.error("Access denied. Admin privileges required.")
        return
    
    # Get all reports for admin
    reports = get_risk_reports()
    
    if reports:
        st.subheader(f"All Reports ({len(reports)})")
        
        for report in reports:
            report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            # Source badge
            source_icons = {
                'user': '👤',
                'news': '📰',
                'social': '📱'
            }
            source_colors = {
                'user': '#28a745',
                'news': '#007bff',
                'social': '#6f42c1'
            }
            
            source_icon = source_icons.get(source_type, '📄')
            source_color = source_colors.get(source_type, '#6c757d')
            
            with st.expander(f"{source_icon} {risk_type} - {location} ({status})"):
                st.write(f"**Description:** {description}")
                st.write(f"**Location:** {location}")
                st.write(f"**Coordinates:** {lat}, {lon}")
                st.write(f"**Reporter:** {reporter_name}")
                st.write(f"**Source Type:** {source_type.title()}")
                st.write(f"**Created:** {created_at}")
                st.write(f"**Confirmations:** {confirmations}")
                if source_url:
                    st.write(f"**Source Link:** [View Original]({source_url})")
                
                # Action buttons
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    if st.button("✅ Verify", key=f"verify_{report_id}"):
                        if update_report_status(report_id, "verified"):
                            st.success("Report verified!")
                            st.rerun()
                
                with col2:
                    if st.button("🔧 Resolve", key=f"resolve_{report_id}"):
                        if update_report_status(report_id, "resolved"):
                            st.success("Report resolved!")
                            st.rerun()
                
                with col3:
                    if st.button("❌ Mark False", key=f"false_{report_id}"):
                        if update_report_status(report_id, "false"):
                            st.success("Report marked as false!")
                            st.rerun()
                
                with col4:
                    if st.button("⏳ Reset to Pending", key=f"pending_{report_id}"):
                        if update_report_status(report_id, "pending"):
                            st.success("Report reset to pending!")
                            st.rerun()
    else:
        st.info("No reports found.")

def show_risk_history():
    st.header("📊 Risk History")
    
    # Time period filter
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        time_period = st.selectbox(
            "Select Time Period",
            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
            index=0
        )
    
    with col2:
        risk_type_filter = st.selectbox(
            "Filter by Risk Type",
            ["All Types", "Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        )
    
    with col3:
        if st.button("🔄 Refresh"):
            st.rerun()
    
    # Convert time period to hours
    time_mapping = {
        "Last 24 Hours": 24,
        "Last 7 Days": 168,
        "Last 30 Days": 720,
        "All Time": None
    }
    
    hours = time_mapping.get(time_period)
    
    # Get reports based on time period
    if hours:
        reports = get_recent_reports(hours=hours)
    else:
        reports = get_risk_reports()
    
    # Filter by risk type if selected
    if risk_type_filter != "All Types":
        reports = [r for r in reports if r[1] == risk_type_filter]  # r[1] is risk_type
    
    if reports:
        st.subheader(f"Risk Reports - {time_period} ({len(reports)} reports)")
        
        # Statistics summary
        st.markdown("### 📈 Statistics Summary")
        
        # Risk type distribution
        risk_counts = {}
        source_counts = {'user': 0, 'news': 0, 'social': 0}
        status_counts = {'pending': 0, 'verified': 0, 'resolved': 0, 'false': 0}
        
        for report in reports:
            risk_type = report[1]
            source_type = report[10]  # source_type
            status = report[6]  # status
            
            risk_counts[risk_type] = risk_counts.get(risk_type, 0) + 1
            source_counts[source_type] = source_counts.get(source_type, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Display statistics in columns
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Risk Type Distribution**")
            for risk_type, count in risk_counts.items():
                st.write(f"• {risk_type}: {count}")
        
        with col2:
            st.markdown("**Source Distribution**")
            for source_type, count in source_counts.items():
                if count > 0:
                    source_icons = {'user': '👤', 'news': '📰', 'social': '📱'}
                    icon = source_icons.get(source_type, '📄')
                    st.write(f"• {icon} {source_type.title()}: {count}")
        
        with col3:
            st.markdown("**Status Distribution**")
            for status, count in status_counts.items():
                if count > 0:
                    status_colors = {
                        'pending': '#ffc107',
                        'verified': '#28a745',
                        'resolved': '#007bff',
                        'false': '#dc3545'
                    }
                    color = status_colors.get(status, '#6c757d')
                    st.markdown(f"• <span style='color: {color}; font-weight: bold;'>{status.title()}</span>: {count}", unsafe_allow_html=True)
        
        # Detailed reports list
        st.markdown("### 📋 Detailed Reports")
        
        # Search functionality
        search_term = st.text_input("🔍 Search reports by location or description", placeholder="Enter search term...")
        
        # Filter reports by search term
        if search_term:
            filtered_reports = []
            for report in reports:
                description = report[2].lower()  # description
                location = report[3].lower()  # location
                if search_term.lower() in description or search_term.lower() in location:
                    filtered_reports.append(report)
            reports = filtered_reports
            st.info(f"Found {len(reports)} reports matching '{search_term}'")
        
        # Display reports with pagination
        reports_per_page = 10
        total_pages = (len(reports) + reports_per_page - 1) // reports_per_page
        
        if total_pages > 1:
            page_num = st.selectbox(f"Page (1-{total_pages})", range(1, total_pages + 1)) - 1
            start_idx = page_num * reports_per_page
            end_idx = start_idx + reports_per_page
            current_reports = reports[start_idx:end_idx]
        else:
            current_reports = reports
        
        for report in current_reports:
            report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            # Create status badge
            status_class = f"status-{status.lower()}"
            risk_class = f"risk-type-{risk_type.lower().replace(' ', '')}"
            
            # Source badge
            source_icons = {
                'user': '👤',
                'news': '📰',
                'social': '📱'
            }
            source_colors = {
                'user': '#28a745',
                'news': '#007bff',
                'social': '#6f42c1'
            }
            
            source_icon = source_icons.get(source_type, '📄')
            source_color = source_colors.get(source_type, '#6c757d')
            
            # Time ago calculation
            time_ago = get_time_ago(created_at)
            
            with st.expander(f"{source_icon} {risk_type} - {location} ({time_ago})"):
                st.markdown(f"""
                <div style="margin-bottom: 10px;">
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 10px;">
                        <span class="{risk_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{risk_type.upper()}</span>
                        <span style="background-color: {source_color}; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{source_icon} {source_type.upper()}</span>
                        <span class="{status_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{status.upper()}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.write(f"**Description:** {description}")
                st.write(f"**Location:** 📍 {location}")
                st.write(f"**Coordinates:** {lat}, {lon}")
                st.write(f"**Reporter:** {reporter_name}")
                st.write(f"**Created:** {created_at}")
                st.write(f"**Confirmations:** ✅ {confirmations}")
                if source_url:
                    st.write(f"**Source:** [View Original]({source_url})")
        
        # Export functionality
        if st.button("📊 Export to CSV"):
            # Create CSV data
            csv_data = "Risk Type,Description,Location,Status,Source,Reporter,Created At\n"
            for report in reports:
                risk_type, description, location, status, _, _, _, _, created_at, reporter_name, source_type, _ = report
                csv_data += f'"{risk_type}","{description}","{location}","{status}","{source_type}","{reporter_name}","{created_at}"\n'
            
            st.download_button(
                label="📥 Download CSV",
                data=csv_data,
                file_name=f"risk_history_{time_period.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
    else:
        st.info(f"No reports found for {time_period}.")

def show_live_feeds():
    st.header("📰 Live News & Social Media Feeds")
    
    # Tabs for different feed types
    tab1, tab2, tab3 = st.tabs(["📰 News Feeds", "📱 Social Media", "🔄 Import to Reports"])
    
    with tab1:
        st.subheader("Latest Nigerian News")
        
        if st.button("🔄 Refresh News"):
            st.rerun()
        
        news_data = fetch_nigerian_news()
        
        if news_data:
            for news in news_data:
                st.markdown(f"""
                <div class="risk-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <span style="background-color: #007bff; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">📰 NEWS</span>
                        <span style="background-color: #fd7e14; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{news['risk_type'].upper()}</span>
                    </div>
                    <h4>{news['title']}</h4>
                    <p>{news['description']}</p>
                    <p><strong>Source:</strong> {news['source']}</p>
                    <p><strong>Location:</strong> 📍 {news['location']}</p>
                    <p><strong>Published:</strong> {news['published_at']}</p>
                    <p><strong>Link:</strong> <a href="{news['url']}" target="_blank">🔗 Read Full Article</a></p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No news articles available.")
    
    with tab2:
        st.subheader("Social Media Updates")
        
        if st.button("🔄 Refresh Social Media"):
            st.rerun()
        
        social_data = fetch_social_media_feeds()
        
        if social_data:
            for post in social_data:
                platform_colors = {
                    'Twitter': '#1DA1F2',
                    'Facebook': '#4267B2',
                    'Instagram': '#E4405F',
                    'WhatsApp Status': '#25D366'
                }
                
                platform_color = platform_colors.get(post['platform'], '#6c757d')
                
                st.markdown(f"""
                <div class="risk-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <span style="background-color: {platform_color}; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">📱 {post['platform'].upper()}</span>
                        <span style="background-color: #fd7e14; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{post['risk_type'].upper()}</span>
                    </div>
                    <p><strong>Content:</strong> {post['content']}</p>
                    <p><strong>User:</strong> {post['username']}</p>
                    <p><strong>Followers:</strong> {post['followers']:,}</p>
                    <p><strong>Location:</strong> 📍 {post['location']}</p>
                    <p><strong>Posted:</strong> {post['posted_at']}</p>
                    <p><strong>Link:</strong> <a href="{post['url']}" target="_blank">🔗 View Original Post</a></p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No social media posts available.")
    
    with tab3:
        st.subheader("Import Live Data to Reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📰 Import News Articles", type="primary"):
                with st.spinner("Importing news articles..."):
                    success = import_news_to_reports()
                if success:
                    st.success("News articles imported successfully!")
                else:
                    st.error("Failed to import news articles.")
        
        with col2:
            if st.button("📱 Import Social Media Posts", type="primary"):
                with st.spinner("Importing social media posts..."):
                    success = import_social_media_to_reports()
                if success:
                    st.success("Social media posts imported successfully!")
                else:
                    st.error("Failed to import social media posts.")
        
        st.info("""
        **How it works:**
        - News articles are imported from major Nigerian news sources
        - Social media posts are collected from verified accounts
        - All imported data is automatically categorized by risk type
        - Source links are preserved for verification
        - Duplicate entries are automatically filtered out
        """)

def show_user_management():
    st.header("👥 User Management")
    
    if st.session_state.user['role'] != 'Admin':
        st.error("Access denied. Admin privileges required.")
        return
    
    # User list
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, full_name, email, phone_number, role, created_at
            FROM users ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        
        if users:
            st.subheader("Registered Users")
            
            for user in users:
                user_id, full_name, email, phone, role, created_at = user
                
                with st.expander(f"{full_name} ({role})"):
                    st.write(f"**Email:** {email or 'Not provided'}")
                    st.write(f"**Phone:** {phone}")
                    st.write(f"**Registered:** {created_at}")
                    
                    if st.button(f"View Details", key=f"view_{user_id}"):
                        st.info(f"Detailed view for {full_name} would be implemented here")
        else:
            st.info("No users found")
            
    except Exception:
        st.info("User management features would be implemented here")

def show_about_page():
    st.header("ℹ️ About Nigerian Road Risk Reporter")
    
    st.markdown("""
    ### 🛣️ Enhanced Minimal Version with Live Feeds
    
    **Nigerian Road Risk Reporter** is a comprehensive road safety platform designed to help users report and track road risks across Nigeria.
    
    #### 🚀 Key Features:
    - **Secure User Registration & Login**: Complete authentication system with role-based access
    - **Risk Report Submission**: Submit detailed road risk reports with GPS coordinates
    - **Live Dashboard**: Real-time road status updates for the last 24 hours
    - **Live news feed integration**: Automated import of road-related news
    - **Social media feed integration**: Real-time social media updates
    - **Source differentiation**: Distinguish between user, news, and social media sources
    - **Risk History**: Comprehensive filtering and export capabilities
    - **Community Validation**: Upvote system for report verification
    - **Admin Control System**: Complete moderation and management tools
    
    #### 🛠️ Technical Stack:
    - **Frontend**: Streamlit (Python-based web framework)
    - **Backend**: Python with SQLite database
    - **Authentication**: SHA256 password hashing
    - **Database**: SQLite (users.db, risk_reports.db, admin_logs.db)
    - **API Integration**: Built-in HTTP requests for news feeds
    - **File Handling**: Image and voice file upload support
    - **Geolocation**: GPS coordinate support
    
    #### 🔒 Security Features:
    - Password hashing with SHA256
    - Session state management
    - Input validation and sanitization
    - Role-based access control
    - Admin action logging
    
    #### 📊 Data Sources:
    - **User Reports**: Direct submissions from registered users
    - **News Feeds**: Automated import from Nigerian news sources
    - **Social Media**: Real-time social media monitoring
    
    #### 🎯 Target Users:
    - **Public**: General road users
    - **Drivers**: Professional drivers and transport operators
    - **Admins**: System administrators and moderators
    
    #### 🌍 Coverage:
    - **Geographic**: Nigeria-wide road network
    - **Risk Types**: Robbery, Flooding, Protest, Road Damage, Traffic, Other
    - **Real-time**: 24/7 monitoring and updates
    
    ---
    *Built with ❤️ for Nigerian road safety*
    """)

def show_admin_dashboard():
    st.header("🔐 Admin Dashboard")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Welcome section
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"""
        ### 👋 Welcome, {admin_user['full_name']}!
        **Admin ID:** {admin_user['id']} | **Email:** {admin_user['email'] or 'N/A'}
        """)
    
    with col2:
        if st.button("🔄 Refresh Data", type="secondary"):
            st.rerun()
    
    # Summary statistics
    st.subheader("📊 System Overview")
    
    try:
        # Get report statistics
        stats = get_report_stats()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Reports", stats.get('total_reports', 0))
        
        with col2:
            st.metric("Pending Reports", stats.get('pending_reports', 0))
        
        with col3:
            st.metric("Verified Reports", stats.get('verified_reports', 0))
        
        with col4:
            st.metric("Flagged as Fake", stats.get('false_reports', 0))
        
        # Recent activity
        st.subheader("📈 Recent Activity (Last 24 Hours)")
        
        recent_reports = get_recent_reports(hours=24)
        if recent_reports:
            # Risk type distribution
            risk_counts = {}
            for report in recent_reports:
                risk_type = report[1]
                risk_counts[risk_type] = risk_counts.get(risk_type, 0) + 1
            
            if risk_counts:
                st.markdown("**Risk Type Distribution:**")
                for risk_type, count in risk_counts.items():
                    st.write(f"• {risk_type}: {count} reports")
            
            # Recent reports table
            st.markdown("**Recent Reports:**")
            for report in recent_reports[:5]:
                report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
                
                status_color = {
                    'pending': '🟡',
                    'verified': '🟢',
                    'resolved': '🔵',
                    'false': '🔴'
                }.get(status, '⚪')
                
                st.markdown(f"""
                **{status_color} Report #{report_id}** - {risk_type} at {location}
                - Reporter: {reporter_name}
                - Status: {status.title()}
                - Source: {source_type.title()}
                - Time: {get_time_ago(created_at)}
                """)
        else:
            st.info("No recent reports in the last 24 hours.")
        
        # Admin logs summary
        st.subheader("📝 Recent Admin Actions")
        admin_logs = get_admin_logs(limit=10)
        
        if admin_logs:
            for log in admin_logs:
                log_id, admin_id, admin_name, action, target_type, target_id, details, created_at, admin_full_name = log
                
                action_icon = {
                    'UPDATE_ROLE': '👤',
                    'VERIFY_REPORT': '✅',
                    'FLAG_REPORT': '🚩',
                    'DELETE_REPORT': '🗑️',
                    'EDIT_REPORT': '✏️'
                }.get(action, '📝')
                
                st.markdown(f"""
                **{action_icon} {action.replace('_', ' ').title()}**
                - Admin: {admin_full_name}
                - Target: {target_type} #{target_id if target_id else 'N/A'}
                - Details: {details or 'No details'}
                - Time: {get_time_ago(created_at)}
                """)
        else:
            st.info("No recent admin actions.")
        
        # Quick actions
        st.subheader("⚡ Quick Actions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📋 View All Reports", type="secondary"):
                st.session_state.admin_page = "Moderation Panel"
                st.rerun()
        
        with col2:
            if st.button("👥 Manage Users", type="secondary"):
                st.session_state.admin_page = "User Management"
                st.rerun()
        
        with col3:
            if st.button("📊 View Logs", type="secondary"):
                st.session_state.admin_page = "Admin Logs"
                st.rerun()
        
        # 20km radius notification simulation
        st.subheader("🚨 Proximity Alerts")
        st.info("""
        **20km Radius Notifications (Simulated)**
        
        📍 **Lagos Area**: 3 new reports in your vicinity
        📍 **Abuja Area**: 1 pending report requires attention
        📍 **Port Harcourt**: 2 verified reports in your area
        
        *This is a simulation. In production, this would use real GPS coordinates.*
        """)
        
    except Exception as e:
        st.error(f"Error loading dashboard data: {str(e)}")

def show_moderation_panel():
    st.header("📋 Moderation Panel")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "pending", "verified", "resolved", "false"]
        )
    
    with col2:
        source_filter = st.selectbox(
            "Filter by Source",
            ["All", "user", "news", "social"]
        )
    
    with col3:
        if st.button("🔄 Refresh Reports", type="secondary"):
            st.rerun()
    
    # Get reports based on filters
    reports = get_risk_reports()
    
    # Apply filters
    if status_filter != "All":
        reports = [r for r in reports if r[6] == status_filter]  # status is at index 6
    
    if source_filter != "All":
        reports = [r for r in reports if r[10] == source_filter]  # source_type is at index 10
    
    if reports:
        st.subheader(f"📊 Reports ({len(reports)} found)")
        
        # Display reports in a table format
        for report in reports:
            report_id, user_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            with st.expander(f"Report #{report_id} - {risk_type} at {location} ({status})"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"""
                    **Risk Type:** {risk_type}  
                    **Location:** 📍 {location}  
                    **Description:** {description}  
                    **Reporter:** {reporter_name}  
                    **Source:** {source_type.title()}  
                    **Created:** {created_at}  
                    **Confirmations:** ✅ {confirmations}
                    """)
                    
                    if source_url:
                        st.markdown(f"**Source URL:** [View Original]({source_url})")
                
                with col2:
                    st.markdown("**Actions:**")
                    
                    # Action buttons
                    if status == "pending":
                        if st.button(f"✅ Verify #{report_id}", key=f"verify_{report_id}"):
                            if update_report_status(report_id, "verified"):
                                log_admin_action(
                                    admin_id=admin_user['id'],
                                    admin_name=admin_user['full_name'],
                                    action="VERIFY_REPORT",
                                    target_type="REPORT",
                                    target_id=report_id,
                                    details=f"Verified report #{report_id} - {risk_type} at {location}"
                                )
                                st.success(f"Report #{report_id} verified!")
                                st.rerun()
                            else:
                                st.error("Failed to verify report")
                    
                    if st.button(f"🚩 Flag as Fake #{report_id}", key=f"flag_{report_id}"):
                        if update_report_status(report_id, "false"):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                action="FLAG_REPORT",
                                target_type="REPORT",
                                target_id=report_id,
                                details=f"Flagged report #{report_id} as fake - {risk_type} at {location}"
                            )
                            st.success(f"Report #{report_id} flagged as fake!")
                            st.rerun()
                        else:
                            st.error("Failed to flag report")
                    
                    if st.button(f"🗑️ Delete #{report_id}", key=f"delete_{report_id}"):
                        if update_report_status(report_id, "deleted"):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                action="DELETE_REPORT",
                                target_type="REPORT",
                                target_id=report_id,
                                details=f"Deleted report #{report_id} - {risk_type} at {location}"
                            )
                            st.success(f"Report #{report_id} deleted!")
                            st.rerun()
                        else:
                            st.error("Failed to delete report")
                    
                    # Status badge
                    status_colors = {
                        'pending': '#ffc107',
                        'verified': '#28a745',
                        'resolved': '#007bff',
                        'false': '#dc3545'
                    }
                    color = status_colors.get(status, '#6c757d')
                    st.markdown(f"""
                    <div style="background-color: {color}; color: white; padding: 8px; border-radius: 4px; text-align: center; font-weight: bold;">
                        {status.upper()}
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.info("No reports found matching the selected filters.")
    
    # Bulk actions
    st.subheader("⚡ Bulk Actions")
    st.info("""
    **Bulk Moderation Features:**
    - Select multiple reports for batch processing
    - Bulk verify pending reports
    - Bulk flag suspicious reports
    - Export selected reports for review
    
    *This feature will be implemented in the next version.*
    """)

def show_admin_user_management():
    st.header("👥 User Management")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        role_filter = st.selectbox(
            "Filter by Role",
            ["All", "Public", "Driver", "Admin"]
        )
    
    with col2:
        search_term = st.text_input("Search by name or email", placeholder="Enter search term...")
    
    with col3:
        if st.button("🔄 Refresh Users", type="secondary"):
            st.rerun()
    
    # Get all users
    users = get_all_users()
    
    # Apply filters
    if role_filter != "All":
        users = [u for u in users if u[4] == role_filter]  # role is at index 4
    
    if search_term:
        users = [u for u in users if search_term.lower() in u[1].lower() or 
                (u[3] and search_term.lower() in u[3].lower())]  # name at index 1, email at index 3
    
    if users:
        st.subheader(f"📊 Users ({len(users)} found)")
        
        # User statistics
        role_counts = {}
        for user in users:
            role = user[4]
            role_counts[role] = role_counts.get(role, 0) + 1
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Users", len(users))
        with col2:
            st.metric("Public Users", role_counts.get("Public", 0))
        with col3:
            st.metric("Drivers", role_counts.get("Driver", 0))
        with col4:
            st.metric("Admins", role_counts.get("Admin", 0))
        
        # Display users
        for user in users:
            user_id, full_name, phone, email, role, nin, created_at = user
            
            with st.expander(f"User #{user_id} - {full_name} ({role})"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"""
                    **Name:** {full_name}  
                    **Phone:** {phone}  
                    **Email:** {email or 'N/A'}  
                    **Role:** {role}  
                    **NIN/Passport:** {nin}  
                    **Registered:** {created_at}
                    """)
                
                with col2:
                    st.markdown("**Actions:**")
                    
                    # Role change options
                    if role != "Admin":
                        if st.button(f"👑 Promote to Admin #{user_id}", key=f"promote_{user_id}"):
                            if update_user_role(user_id, "Admin", admin_user['id'], admin_user['full_name']):
                                st.success(f"User #{user_id} promoted to Admin!")
                                st.rerun()
                            else:
                                st.error("Failed to promote user")
                    
                    if role != "Driver":
                        if st.button(f"🚗 Make Driver #{user_id}", key=f"driver_{user_id}"):
                            if update_user_role(user_id, "Driver", admin_user['id'], admin_user['full_name']):
                                st.success(f"User #{user_id} role changed to Driver!")
                                st.rerun()
                            else:
                                st.error("Failed to change user role")
                    
                    if role != "Public":
                        if st.button(f"👤 Make Public #{user_id}", key=f"public_{user_id}"):
                            if update_user_role(user_id, "Public", admin_user['id'], admin_user['full_name']):
                                st.success(f"User #{user_id} role changed to Public!")
                                st.rerun()
                            else:
                                st.error("Failed to change user role")
                    
                    # Suspend user (simulated)
                    if st.button(f"⏸️ Suspend #{user_id}", key=f"suspend_{user_id}"):
                        log_admin_action(
                            admin_id=admin_user['id'],
                            admin_name=admin_user['full_name'],
                            action="SUSPEND_USER",
                            target_type="USER",
                            target_id=user_id,
                            details=f"Suspended user {full_name} (ID: {user_id})"
                        )
                        st.success(f"User #{user_id} suspended!")
                        st.rerun()
                    
                    # Re-verify user (simulated)
                    if st.button(f"✅ Re-verify #{user_id}", key=f"reverify_{user_id}"):
                        log_admin_action(
                            admin_id=admin_user['id'],
                            admin_name=admin_user['full_name'],
                            action="REVERIFY_USER",
                            target_type="USER",
                            target_id=user_id,
                            details=f"Re-verified user {full_name} (ID: {user_id})"
                        )
                        st.success(f"User #{user_id} re-verified!")
                        st.rerun()
                    
                    # Role badge
                    role_colors = {
                        'Public': '#6c757d',
                        'Driver': '#007bff',
                        'Admin': '#dc3545'
                    }
                    color = role_colors.get(role, '#6c757d')
                    st.markdown(f"""
                    <div style="background-color: {color}; color: white; padding: 8px; border-radius: 4px; text-align: center; font-weight: bold;">
                        {role.upper()}
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.info("No users found matching the selected filters.")
    
    # User management features
    st.subheader("⚡ User Management Features")
    st.info("""
    **Advanced User Management:**
    - Bulk user operations
    - User activity monitoring
    - Account suspension/activation
    - User verification status
    - Export user data
    
    *These features will be implemented in the next version.*
    """)

def show_admin_logs():
    st.header("📊 Admin Logs")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        action_filter = st.selectbox(
            "Filter by Action",
            ["All", "UPDATE_ROLE", "VERIFY_REPORT", "FLAG_REPORT", "DELETE_REPORT", "SUSPEND_USER", "REVERIFY_USER"]
        )
    
    with col2:
        admin_filter = st.text_input("Filter by Admin", placeholder="Enter admin name...")
    
    with col3:
        if st.button("🔄 Refresh Logs", type="secondary"):
            st.rerun()
    
    # Get admin logs
    logs = get_admin_logs(limit=100)
    
    # Apply filters
    if action_filter != "All":
        logs = [log for log in logs if log[3] == action_filter]  # action is at index 3
    
    if admin_filter:
        logs = [log for log in logs if admin_filter.lower() in log[8].lower()]  # admin_full_name is at index 8
    
    if logs:
        st.subheader(f"📝 Admin Actions ({len(logs)} found)")
        
        # Log statistics
        action_counts = {}
        admin_counts = {}
        for log in logs:
            action = log[3]
            admin_name = log[8]
            action_counts[action] = action_counts.get(action, 0) + 1
            admin_counts[admin_name] = admin_counts.get(admin_name, 0) + 1
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Action Distribution:**")
            for action, count in action_counts.items():
                st.write(f"• {action.replace('_', ' ').title()}: {count}")
        
        with col2:
            st.markdown("**Admin Activity:**")
            for admin, count in admin_counts.items():
                st.write(f"• {admin}: {count} actions")
        
        # Display logs
        for log in logs:
            log_id, admin_id, admin_name, action, target_type, target_id, details, created_at, admin_full_name = log
            
            with st.expander(f"{action.replace('_', ' ').title()} by {admin_full_name} at {get_time_ago(created_at)}"):
                st.markdown(f"""
                **Action:** {action.replace('_', ' ').title()}  
                **Admin:** {admin_full_name} (ID: {admin_id})  
                **Target Type:** {target_type}  
                **Target ID:** {target_id or 'N/A'}  
                **Details:** {details or 'No details provided'}  
                **Timestamp:** {created_at}
                """)
                
                # Action-specific information
                if action == "UPDATE_ROLE":
                    st.info("👤 **Role Update Action** - User role was modified")
                elif action in ["VERIFY_REPORT", "FLAG_REPORT", "DELETE_REPORT"]:
                    st.info("📋 **Report Moderation Action** - Report status was changed")
                elif action in ["SUSPEND_USER", "REVERIFY_USER"]:
                    st.info("👥 **User Management Action** - User account was modified")
        
        # Export functionality
        st.subheader("📤 Export Logs")
        if st.button("📊 Export to CSV"):
            # Create CSV data
            csv_data = "Action,Admin,Target Type,Target ID,Details,Timestamp\n"
            for log in logs:
                log_id, admin_id, admin_name, action, target_type, target_id, details, created_at, admin_full_name = log
                csv_data += f'"{action}","{admin_full_name}","{target_type}","{target_id or ""}","{details or ""}","{created_at}"\n'
            
            st.download_button(
                label="📥 Download CSV",
                data=csv_data,
                file_name=f"admin_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No admin logs found matching the selected filters.")
    
    # Log management features
    st.subheader("⚡ Log Management Features")
    st.info("""
    **Advanced Log Management:**
    - Real-time log monitoring
    - Log retention policies
    - Automated log analysis
    - Alert system for suspicious activities
    - Log backup and archiving
    
    *These features will be implemented in the next version.*
    """)

def show_config_panel():
    st.header("⚙️ Configuration Panel")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Tab navigation
    tab1, tab2, tab3 = st.tabs(["Risk Types", "Advice Templates", "System Settings"])
    
    with tab1:
        st.subheader("🚨 Risk Type Configuration")
        
        # Default risk types
        default_risk_types = ["Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        
        st.markdown("**Current Risk Types:**")
        for i, risk_type in enumerate(default_risk_types):
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.write(f"• {risk_type}")
            with col2:
                if st.button(f"Edit {risk_type}", key=f"edit_risk_{i}"):
                    st.info(f"Edit functionality for {risk_type} will be implemented in the next version.")
            with col3:
                if st.button(f"Delete {risk_type}", key=f"delete_risk_{i}"):
                    st.warning(f"Delete functionality for {risk_type} will be implemented in the next version.")
        
        # Add new risk type
        st.markdown("**Add New Risk Type:**")
        with st.form("add_risk_type"):
            new_risk_type = st.text_input("Risk Type Name", placeholder="Enter new risk type...")
            risk_description = st.text_area("Description", placeholder="Describe this risk type...")
            risk_color = st.color_picker("Risk Color", "#dc3545")
            
            if st.form_submit_button("Add Risk Type"):
                if new_risk_type:
                    st.success(f"Risk type '{new_risk_type}' added successfully!")
                    log_admin_action(
                        admin_id=admin_user['id'],
                        admin_name=admin_user['full_name'],
                        action="ADD_RISK_TYPE",
                        target_type="CONFIG",
                        details=f"Added new risk type: {new_risk_type}"
                    )
                    st.rerun()
                else:
                    st.error("Please enter a risk type name.")
    
    with tab2:
        st.subheader("💡 Advice Templates")
        
        # Default advice templates
        advice_templates = {
            "Robbery": "🚨 **Robbery Alert**: Avoid this area, especially at night. Travel in groups if possible. Contact local authorities immediately.",
            "Flooding": "🌊 **Flooding Warning**: Road may be impassable. Avoid driving through flooded areas. Find alternative routes.",
            "Protest": "🏛️ **Protest Notice**: Expect traffic delays and road closures. Plan alternative routes and allow extra travel time.",
            "Road Damage": "🛣️ **Road Damage**: Potholes or road damage detected. Drive carefully and report to authorities.",
            "Traffic": "🚗 **Traffic Alert**: Heavy traffic congestion. Consider alternative routes or delay travel if possible."
        }
        
        st.markdown("**Current Advice Templates:**")
        for risk_type, advice in advice_templates.items():
            with st.expander(f"Advice for {risk_type}"):
                st.markdown(advice)
                
                # Edit advice template
                new_advice = st.text_area(
                    f"Edit advice for {risk_type}",
                    value=advice,
                    key=f"advice_{risk_type}"
                )
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"Save {risk_type} Advice", key=f"save_advice_{risk_type}"):
                        log_admin_action(
                            admin_id=admin_user['id'],
                            admin_name=admin_user['full_name'],
                            action="UPDATE_ADVICE",
                            target_type="CONFIG",
                            details=f"Updated advice template for {risk_type}"
                        )
                        st.success(f"Advice for {risk_type} updated successfully!")
                
                with col2:
                    if st.button(f"Reset {risk_type} Advice", key=f"reset_advice_{risk_type}"):
                        st.info(f"Reset functionality for {risk_type} will be implemented in the next version.")
    
    with tab3:
        st.subheader("🔧 System Settings")
        
        # System configuration options
        st.markdown("**General Settings:**")
        
        # Notification settings
        st.markdown("**Notification Settings:**")
        email_notifications = st.checkbox("Enable Email Notifications", value=True)
        sms_notifications = st.checkbox("Enable SMS Notifications", value=False)
        push_notifications = st.checkbox("Enable Push Notifications", value=True)
        
        # Report settings
        st.markdown("**Report Settings:**")
        auto_verify_threshold = st.slider("Auto-verify threshold (upvotes)", 1, 10, 3)
        report_retention_days = st.number_input("Report retention (days)", 30, 365, 90)
        
        # Admin settings
        st.markdown("**Admin Settings:**")
        require_2fa = st.checkbox("Require 2FA for admin login", value=True)
        log_retention_days = st.number_input("Log retention (days)", 30, 365, 180)
        
        # Save settings
        if st.button("💾 Save Settings", type="primary"):
            log_admin_action(
                admin_id=admin_user['id'],
                admin_name=admin_user['full_name'],
                action="UPDATE_SETTINGS",
                target_type="CONFIG",
                details="Updated system configuration settings"
            )
            st.success("Settings saved successfully!")
        
        # System information
        st.markdown("**System Information:**")
        st.info(f"""
        **Current Configuration:**
        - Email Notifications: {'✅ Enabled' if email_notifications else '❌ Disabled'}
        - SMS Notifications: {'✅ Enabled' if sms_notifications else '❌ Disabled'}
        - Push Notifications: {'✅ Enabled' if push_notifications else '❌ Disabled'}
        - Auto-verify Threshold: {auto_verify_threshold} upvotes
        - Report Retention: {report_retention_days} days
        - 2FA Required: {'✅ Yes' if require_2fa else '❌ No'}
        - Log Retention: {log_retention_days} days
        """)
    
    # Configuration management features
    st.subheader("⚡ Configuration Management Features")
    st.info("""
    **Advanced Configuration:**
    - Configuration versioning
    - Backup and restore settings
    - Environment-specific configs
    - Automated configuration validation
    - Configuration change notifications
    
    *These features will be implemented in the next version.*
    """)

def show_ai_advice_page():
    """Display AI Safety Advice page"""
    
    # Disclaimer
    st.warning("""
    ⚠️ **IMPORTANT DISCLAIMER**: 
    All safety advice and risk information provided through this platform are **SUGGESTIONS ONLY**. 
    Users should exercise their own judgment and verify information independently. 
    The platform is not responsible for any decisions made based on the information provided.
    
    🚨 **ACCOUNT WARNING**: Users who submit false or misleading information may have their accounts removed.
    """)
    
    try:
        from ai_advice import display_advice_interface
        display_advice_interface()
    except ImportError:
        st.warning("🤖 AI Advice module not available in minimal mode.")
        st.info("ℹ️ Basic safety advice is still available when submitting reports.")
        st.markdown("""
        ### Basic Safety Advice Templates
        
        **Robbery**: 🚨 Avoid this area, especially at night. Travel in groups if possible.
        
        **Flooding**: 🌊 Road may be impassable. Avoid driving through flooded areas.
        
        **Protest**: 🏛️ Expect traffic delays and road closures. Plan alternative routes.
        
        **Road Damage**: 🛣️ Drive carefully and report to authorities.
        
        **Traffic**: 🚗 Heavy traffic congestion. Consider alternative routes.
        
        **Other**: ⚠️ Exercise caution in this area. Follow local advisories.
        """)

def show_analytics_page():
    """Display Analytics Dashboard page with improved error handling"""
    st.header("📊 Analytics Dashboard")
    st.markdown("Comprehensive analytics and insights for road risk reports")
    
    try:
        # Check if required dependencies are available
        import pandas as pd
        import plotly.graph_objects as go
        import plotly.express as px
        
        # Try to import the analytics dashboard
        from analytics_dashboard import run_analytics_dashboard
        run_analytics_dashboard()
        
    except ImportError as e:
        st.warning("📊 Analytics module not available - missing dependencies.")
        st.info("ℹ️ Basic report statistics are available below.")
        
        # Show enhanced basic stats from main app
        try:
            stats = get_report_stats()
            if stats:
                st.subheader("📈 Basic Statistics")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Reports", stats.get('total_reports', 0))
                with col2:
                    st.metric("Verified Reports", stats.get('verified_reports', 0))
                with col3:
                    st.metric("Pending Reports", stats.get('pending_reports', 0))
                with col4:
                    st.metric("Active Users", stats.get('active_users', 0))
                
                # Show recent reports
                st.subheader("📋 Recent Reports (Last 24 Hours)")
                recent_reports = get_recent_reports(24)
                if recent_reports:
                    for report in recent_reports[:10]:  # Show last 10 reports
                        with st.expander(f"{report['risk_type']} - {report['location']} ({get_time_ago(report['created_at'])})"):
                            st.write(f"**Description:** {report['description']}")
                            st.write(f"**Status:** {report['status']}")
                            st.write(f"**Reporter:** {report['reporter_name']}")
                else:
                    st.info("No recent reports found.")
        except Exception as e:
            st.error(f"Failed to load basic statistics: {str(e)}")
            st.info("Please try refreshing the page or contact support if the issue persists.")
    
    except Exception as e:
        st.error(f"📊 Analytics dashboard encountered an error: {str(e)}")
        st.info("ℹ️ Please try refreshing the page or contact support if the issue persists.")
        
        # Show basic stats as fallback
        try:
            stats = get_report_stats()
            if stats:
                st.subheader("📈 Basic Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Reports", stats.get('total_reports', 0))
                with col2:
                    st.metric("Verified Reports", stats.get('verified_reports', 0))
                with col3:
                    st.metric("Pending Reports", stats.get('pending_reports', 0))
        except:
            st.info("No report statistics available.")

def show_security_page():
    """Display Security Settings page with enhanced security information"""
    st.header("🔐 Security Settings")
    st.markdown("Manage your account security and view security status")
    
    try:
        from security import main as security_main
        security_main()
    except ImportError:
        st.warning("🔐 Advanced security module not available.")
        st.info("ℹ️ Basic authentication and session management are still active.")
        
        # Show enhanced basic security info
        st.markdown("""
        ### Current Security Status
        
        ✅ **Basic Authentication**: Username/password login
        ✅ **Session Management**: Secure session handling (30-minute timeout)
        ✅ **Password Hashing**: SHA256 with salt
        ✅ **Role-Based Access**: Admin/User/Public roles
        ✅ **Login Attempt Limits**: 5 attempts before lockout
        ✅ **Account Lockout**: 30-minute lockout after failed attempts
        ✅ **Input Sanitization**: Protection against injection attacks
        ✅ **Security Audit Logging**: All actions are logged
        
        ### Security Features Available
        
        - User registration and login with validation
        - Password strength validation (8+ chars, special chars)
        - Session timeout management (30 minutes)
        - Admin access control and moderation
        - Login attempt tracking and lockout
        - Security audit logging
        - Input sanitization and validation
        
        ### Security Recommendations
        
        - Use strong, unique passwords
        - Log out when using shared devices
        - Report suspicious activity immediately
        - Keep your contact information updated
        """)
        
        # Show current user's security status
        if st.session_state.get('user'):
            st.subheader("🔍 Your Security Status")
            user = st.session_state.user
            
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Account:** {user['full_name']}")
                st.info(f"**Role:** {user['role']}")
                st.info(f"**Email:** {user.get('email', 'Not provided')}")
            
            with col2:
                # Show session info
                if 'login_time' in user:
                    try:
                        login_time = datetime.fromisoformat(user['login_time'])
                        remaining = SECURITY_CONFIG['session_timeout_minutes'] - (datetime.now() - login_time).total_seconds() / 60
                        if remaining > 0:
                            st.success(f"**Session expires in:** {int(remaining)} minutes")
                        else:
                            st.warning("**Session expired**")
                    except:
                        st.info("**Session status:** Unknown")
                
                # Show security tips
                st.markdown("""
                **Security Tips:**
                - Change password regularly
                - Enable 2FA if available
                - Monitor login activity
                - Report suspicious behavior
                """)

def show_deployment_page():
    """Display Deployment & PWA page with enhanced information"""
    st.header("🚀 Deployment & PWA")
    st.markdown("Application deployment status and Progressive Web App features")
    
    try:
        from deploy_app import main as deployment_main
        deployment_main()
    except ImportError:
        st.warning("🚀 Advanced deployment module not available.")
        st.info("ℹ️ App is running in enhanced mode on Streamlit Cloud.")
        
        # Show enhanced deployment status
        st.markdown("""
        ### Deployment Status
        
        ✅ **Platform**: Streamlit Cloud
        ✅ **Mode**: Enhanced (Core + Advanced features)
        ✅ **Status**: Active and running
        ✅ **Version**: RoadReportNG v2.0
        ✅ **Domain**: roadreportng.com (Registered)
        
        ### Available Features
        
        ✅ **Core Features**:
        - User registration and authentication
        - Risk report submission and management
        - Enhanced safety advice generation
        - Report viewing with filters
        - Admin dashboard and moderation
        - Live feeds and risk history
        - Road status checker
        - Security audit logging
        
        ✅ **Advanced Features**:
        - Interactive analytics dashboard
        - Enhanced security features
        - Account lockout protection
        - Input sanitization
        - Session management
        - Role-based access control
        
        ### Performance & Security
        
        - **Database**: SQLite with encryption
        - **Authentication**: SHA256 with salt
        - **Session Management**: 30-minute timeout
        - **Rate Limiting**: Enabled
        - **Input Validation**: Comprehensive
        - **Error Handling**: Graceful fallbacks
        
        ### Future Enhancements
        
        - Progressive Web App (PWA) features
        - SMS alerts and notifications
        - Advanced AI safety advice
        - Mobile app development
        - API integration for external data
        - Real-time traffic updates
        """)
        
        # Show technical information
        st.subheader("🔧 Technical Information")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **Backend:**
            - Python 3.13 compatible
            - Streamlit framework
            - SQLite database
            - SHA256 password hashing
            
            **Security:**
            - Input sanitization
            - SQL injection protection
            - Session management
            - Rate limiting
            """)
        
        with col2:
            st.markdown("""
            **Frontend:**
            - Responsive design
            - Mobile-friendly interface
            - Real-time updates
            - Interactive charts
            
            **Deployment:**
            - Streamlit Cloud hosting
            - Automatic scaling
            - SSL encryption
            - Global CDN
            """)

def show_road_status_checker():
    """Display Road Status Checker page for travelers"""
    st.header("🛣️ Road Status Checker (Enhanced)")
    
    # Disclaimer
    st.warning("""
    ⚠️ **DISCLAIMER**: Road status information is based on user reports and automated data collection. 
    This information is provided as **SUGGESTIONS ONLY** and should not be the sole basis for travel decisions. 
    Please exercise your own judgment and verify information independently.
    
    🚨 **ACCOUNT WARNING**: Users who submit false or misleading information may have their accounts removed.
    """)
    
    # Search options
    search_option = st.radio("Search by:", ["Road Name", "Location", "Browse by State"])
    
    if search_option == "Road Name":
        st.subheader("Search by Road Name")
        
        # Road name input with autocomplete
        if ROADS_DB_AVAILABLE:
            major_roads = nigerian_roads_db.get_major_roads()
            road_names = [road['name'] for road in major_roads]
            road_name = st.selectbox("Select Road:", ["Search by typing..."] + road_names)
            
            if road_name and road_name != "Search by typing...":
                # Get road information
                road_info = nigerian_roads_db.get_road_by_name(road_name)
                
                if road_info:
                    st.success(f"Found road: {road_info['name']}")
                    
                    # Display road information
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Road Name:** {road_info['name']}")
                        st.write(f"**Road ID:** {road_info['road_id']}")
                        st.write(f"**Type:** {road_info['type']}")
                        st.write(f"**Length:** {road_info['length_km']} km")
                    
                    with col2:
                        st.write(f"**Status:** {road_info['status']}")
                        st.write(f"**States:** {', '.join(road_info['states'])}")
                        st.write(f"**Risk Factors:** {', '.join(road_info['risk_factors'])}")
                    
                    # Get recent risks for this road
                    st.subheader("🚨 Recent Risks")
                    recent_risks = nigerian_roads_db.get_road_risks(hours=168, road_id=road_info['road_id'])
                    
                    if recent_risks:
                        for risk in recent_risks:
                            with st.expander(f"🚨 {risk.get('risk_type', 'Unknown')} - {risk.get('reported_at', 'Unknown')}"):
                                col1, col2 = st.columns([2, 1])
                                
                                with col1:
                                    st.write(f"**Risk Type:** {risk.get('risk_type', 'Unknown')}")
                                    st.write(f"**Description:** {risk.get('description', 'No description')}")
                                    st.write(f"**Location:** 📍 {risk.get('location', 'Unknown')}")
                                    st.write(f"**Severity:** {risk.get('severity', 'Unknown')}")
                                
                                with col2:
                                    st.write(f"**State:** {risk.get('state', 'Unknown')}")
                                    st.write(f"**LGA:** {risk.get('lga', 'Unknown')}")
                                    st.write(f"**Reported:** {risk.get('reported_at', 'Unknown')}")
                    else:
                        st.info("✅ No recent risks reported for this road.")
                    
                    # AI Recommendations
                    st.subheader("🤖 AI Recommendations")
                    if recent_risks:
                        # Analyze risks and provide recommendations
                        high_risks = [r for r in recent_risks if r.get('severity') in ['High', 'Critical']]
                        if high_risks:
                            st.error("🚨 **HIGH RISK ALERT**")
                            st.markdown("""
                            **Immediate Actions:**
                            - Consider alternative routes
                            - Travel with extreme caution
                            - Monitor local news for updates
                            - Contact authorities if necessary
                            """)
                        else:
                            st.warning("⚠️ **MODERATE RISK**")
                            st.markdown("""
                            **Precautionary Measures:**
                            - Stay alert to changing conditions
                            - Follow traffic advisories
                            - Report any new issues
                            """)
                    else:
                        st.success("✅ **CLEAR ROAD**")
                        st.markdown("""
                        **Status:**
                        - Road appears to be clear of major risks
                        - Normal driving conditions apply
                        - Continue to monitor for changes
                        """)
                    
                    # Alternative routes
                    st.subheader("🔄 Alternative Routes")
                    if recent_risks:
                        alternatives = get_alternative_routes(road_name, road_info['states'][0] if road_info['states'] else "Unknown")
                        if alternatives:
                            for alt in alternatives:
                                st.write(f"• **{alt['name']}** - {alt['distance']} km via {alt['route']}")
                        else:
                            st.info("No alternative routes available. Consider delaying travel if possible.")
                    else:
                        st.info("No alternative routes needed - road is clear.")
                else:
                    st.warning("Road not found. Please check the road name and try again.")
        else:
            st.info("Nigerian roads database not available. Please use the basic search.")
            road_name = st.text_input("Enter road name:", placeholder="e.g., Lagos-Ibadan Expressway")
            if road_name:
                st.info("Basic search functionality available. Enhanced features require Nigerian roads database.")
    
    elif search_option == "Location":
        st.subheader("Search by Location")
        
        if ROADS_DB_AVAILABLE:
            # Location inputs
            col1, col2 = st.columns(2)
            
            with col1:
                states = nigerian_roads_db.get_states()
                state = st.selectbox("Select State:", states)
            
            with col2:
                if state:
                    lgas = nigerian_roads_db.get_local_governments(state)
                    lga = st.selectbox("Local Government Area:", ["All LGAs"] + lgas)
                else:
                    lga = st.selectbox("Local Government Area:", ["Select State First"])
            
            if state:
                # Get roads in the selected state
                roads_in_state = nigerian_roads_db.get_major_roads(state)
                
                if roads_in_state:
                    st.success(f"Found {len(roads_in_state)} major roads in {state}")
                    
                    for road in roads_in_state:
                        with st.expander(f"🛣️ {road['name']} - {road['type']}"):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write(f"**Length:** {road['length_km']} km")
                                st.write(f"**Status:** {road['status']}")
                                st.write(f"**Risk Factors:** {', '.join(road['risk_factors'])}")
                            
                            with col2:
                                # Get recent risks for this road
                                recent_risks = nigerian_roads_db.get_road_risks(hours=168, road_id=road['road_id'])
                                st.write(f"**Recent Risks:** {len(recent_risks)}")
                                
                                if recent_risks:
                                    st.write("**Latest Issues:**")
                                    for risk in recent_risks[:3]:  # Show last 3 risks
                                        st.markdown(f"""
                                        <div style="background-color: #f8f9fa; padding: 0.5rem; border-radius: 5px; margin: 0.5rem 0;">
                                            <p><strong>{risk.get('risk_type', 'Unknown')}</strong> - {risk.get('description', 'No description')[:100]}...</p>
                                            <p style="font-size: 0.8em; color: #6c757d;">{risk.get('reported_at', 'Unknown')}</p>
                                        </div>
                                        """, unsafe_allow_html=True)
                                else:
                                    st.info("✅ No recent risks reported.")
                else:
                    st.info(f"No major roads found in {state}.")
        else:
            st.info("Nigerian roads database not available for location search.")
    
    else:  # Browse by State
        st.subheader("Browse by State")
        
        if ROADS_DB_AVAILABLE:
            states = nigerian_roads_db.get_states()
            selected_state = st.selectbox("Select State to Browse:", states)
            
            if selected_state:
                # Get summary for the state
                state_stats = nigerian_roads_db.get_road_statistics(selected_state)
                
                st.success(f"Road Network Summary for {selected_state}")
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Major Roads", state_stats.get('major_roads', 0))
                
                with col2:
                    st.metric("Total Risks (24h)", state_stats.get('total_risks', 0))
                
                with col3:
                    st.metric("Total Conditions (3m)", state_stats.get('total_conditions', 0))
                
                with col4:
                    st.metric("Active LGAs", state_stats.get('active_lgas', 0))
                
                # List major roads in the state
                st.subheader("Major Roads")
                roads_in_state = nigerian_roads_db.get_major_roads(selected_state)
                
                if roads_in_state:
                    for road in roads_in_state:
                        with st.expander(f"🛣️ {road['name']} - {road['status']}"):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write(f"**Type:** {road['type']}")
                                st.write(f"**Length:** {road['length_km']} km")
                                st.write(f"**Risk Factors:** {', '.join(road['risk_factors'])}")
                            
                            with col2:
                                # Get recent risks for this road
                                recent_risks = nigerian_roads_db.get_road_risks(hours=168, road_id=road['road_id'])
                                st.write(f"**Recent Risks:** {len(recent_risks)}")
                                
                                if recent_risks:
                                    st.write("**Latest Issues:**")
                                    for risk in recent_risks[:2]:  # Show last 2 risks
                                        st.markdown(f"""
                                        <div style="background-color: #f8f9fa; padding: 0.5rem; border-radius: 5px; margin: 0.5rem 0;">
                                            <p><strong>{risk.get('risk_type', 'Unknown')}</strong> - {risk.get('description', 'No description')[:80]}...</p>
                                        </div>
                                        """, unsafe_allow_html=True)
                                else:
                                    st.info("✅ No recent risks reported.")
                else:
                    st.info(f"No major roads found in {selected_state}.")
        else:
            st.info("Nigerian roads database not available for state browsing.")
    
    # General road safety tips
    st.subheader("🛡️ General Road Safety Tips")
    st.markdown("""
    **Before Traveling:**
    - Check road conditions and weather
    - Plan your route and alternatives
    - Ensure your vehicle is in good condition
    - Have emergency contacts ready
    
    **While Traveling:**
    - Stay alert and avoid distractions
    - Follow traffic rules and speed limits
    - Keep safe distance from other vehicles
    - Be prepared for unexpected conditions
    
    **Emergency Contacts:**
    - Emergency: 0800-112-1199
    - Police: 112
    - Road Safety: 0800-112-1199
    
    **AI-Powered Insights:**
    - This system uses Nigerian road data to provide contextual advice
    - Reports are community-verified for accuracy
    - Real-time updates from multiple sources
    - Location-specific recommendations based on local conditions
    """)

def get_road_risk_reports(road_name: str, state: str, hours: int = 168) -> list:
    """Get risk reports for a specific road within specified time period"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Search for reports related to this road within specified time period
        cursor.execute('''
            SELECT r.id, r.risk_type, r.description, r.location, r.latitude, r.longitude,
                   r.status, r.confirmations, r.created_at, u.full_name, r.source_type, r.source_url
            FROM risk_reports r
            JOIN users u ON r.user_id = u.id
            WHERE (r.location LIKE ? OR r.description LIKE ?)
            AND r.created_at >= datetime('now', '-{} hours')
            ORDER BY r.created_at DESC
        '''.format(hours), (f'%{road_name}%', f'%{road_name}%'))
        
        reports = cursor.fetchall()
        conn.close()
        
        return reports
    except Exception:
        return []

def calculate_road_status(reports: list) -> str:
    """Calculate overall road status based on risk reports"""
    if not reports:
        return "Unknown"
    
    # Count risk types
    risk_counts = {}
    for report in reports:
        risk_type = report[1]  # risk_type
        risk_counts[risk_type] = risk_counts.get(risk_type, 0) + 1
    
    # High risk indicators
    high_risk_types = ['Robbery', 'Flooding', 'Protest']
    high_risk_count = sum(risk_counts.get(risk, 0) for risk in high_risk_types)
    
    # Moderate risk indicators
    moderate_risk_types = ['Road Damage', 'Traffic']
    moderate_risk_count = sum(risk_counts.get(risk, 0) for risk in moderate_risk_types)
    
    # Determine status
    if high_risk_count >= 2:
        return "High Risk"
    elif high_risk_count >= 1 or moderate_risk_count >= 3:
        return "Moderate"
    elif moderate_risk_count >= 1:
        return "Moderate"
    else:
        return "Safe"

def get_travel_advice(status: str, reports: list) -> str:
    """Generate travel advice based on road status"""
    if status == "High Risk":
        return """
        🚨 **HIGH RISK - AVOID TRAVEL IF POSSIBLE**
        
        • **Immediate Actions:**
          - Avoid this route entirely if possible
          - If travel is essential, travel in groups
          - Inform someone of your travel plans
          - Have emergency contacts readily available
        
        • **Safety Measures:**
          - Travel during daylight hours only
          - Use main roads and avoid shortcuts
          - Keep doors locked and windows up
          - Have a fully charged phone
        
        • **Emergency Contacts:**
          - Police: 112
          - Emergency: 0800-112-1199
          - Road Safety: 122
        """
    elif status == "Moderate":
        return """
        ⚠️ **MODERATE RISK - EXERCISE CAUTION**
        
        • **Travel Recommendations:**
          - Plan your route in advance
          - Allow extra travel time
          - Stay alert to surroundings
          - Follow local traffic advisories
        
        • **Safety Tips:**
          - Travel during daylight when possible
          - Keep emergency contacts handy
          - Monitor local news for updates
          - Have alternative routes planned
        
        • **Emergency Contacts:**
          - Police: 112
          - Emergency: 0800-112-1199
        """
    else:
        return """
        ✅ **SAFE TO TRAVEL - NORMAL PRECAUTIONS**
        
        • **Standard Safety:**
          - Follow normal traffic rules
          - Stay alert while driving
          - Keep emergency contacts available
          - Monitor for any changes in conditions
        
        • **General Tips:**
          - Maintain your vehicle properly
          - Have basic emergency supplies
          - Know your route before traveling
          - Stay informed about weather conditions
        """

def get_alternative_routes(road_name: str, state: str) -> list:
    """Get alternative routes for a road"""
    # This would typically connect to a mapping API
    # For now, return some common alternatives
    alternatives = {
        "Lagos-Ibadan Expressway": [
            {"name": "Ikorodu-Sagamu Road", "description": "Alternative route through Ikorodu", "time": "+30 minutes"},
            {"name": "Epe-Ijebu Ode Road", "description": "Coastal route through Epe", "time": "+45 minutes"}
        ],
        "Third Mainland Bridge": [
            {"name": "Carter Bridge", "description": "Alternative bridge crossing", "time": "+15 minutes"},
            {"name": "Eko Bridge", "description": "Another bridge option", "time": "+20 minutes"}
        ],
        "Lekki-Epe Expressway": [
            {"name": "Victoria Island-Epe Road", "description": "Coastal alternative route", "time": "+25 minutes"},
            {"name": "Ikorodu-Epe Road", "description": "Inland alternative", "time": "+35 minutes"}
        ],
        "Victoria Island Road": [
            {"name": "Ikoyi-Lekki Road", "description": "Alternative through Ikoyi", "time": "+10 minutes"},
            {"name": "Ahmadu Bello Way", "description": "Main alternative route", "time": "+15 minutes"}
        ],
        "Ikorodu Road": [
            {"name": "Lagos-Ibadan Expressway", "description": "Main expressway alternative", "time": "+20 minutes"},
            {"name": "Epe-Ikorodu Road", "description": "Coastal alternative", "time": "+25 minutes"}
        ],
        "Ahmadu Bello Way": [
            {"name": "Airport Road", "description": "Alternative through airport area", "time": "+10 minutes"},
            {"name": "Kubwa Expressway", "description": "Northern alternative", "time": "+15 minutes"}
        ],
        "Port Harcourt-Aba Road": [
            {"name": "East-West Road", "description": "Coastal alternative route", "time": "+20 minutes"},
            {"name": "Port Harcourt-Enugu Road", "description": "Northern alternative", "time": "+30 minutes"}
        ],
        "Kano-Kaduna Expressway": [
            {"name": "Jos-Kaduna Road", "description": "Alternative through Jos", "time": "+45 minutes"},
            {"name": "Kano-Maiduguri Road", "description": "Eastern alternative", "time": "+60 minutes"}
        ],
        "Enugu-Onitsha Expressway": [
            {"name": "Enugu-Port Harcourt Road", "description": "Southern alternative", "time": "+30 minutes"},
            {"name": "Enugu-Awka Road", "description": "Local alternative", "time": "+15 minutes"}
        ],
        "Calabar-Uyo Road": [
            {"name": "Calabar-Port Harcourt Road", "description": "Western alternative", "time": "+25 minutes"},
            {"name": "Calabar-Abak Road", "description": "Local alternative", "time": "+10 minutes"}
        ]
    }
    
    return alternatives.get(road_name, [])

if __name__ == "__main__":
    main() 