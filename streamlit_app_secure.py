#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - SECURE VERSION
Critical security fixes implemented
Python 3.13 compatible - Streamlit Cloud ready
"""

import streamlit as st
import sqlite3
import re
import json
import os
import time
from datetime import datetime, timedelta
import base64
import io
from typing import Dict, List, Optional, Tuple

# Import security fixes
try:
    from security_fixes import (
        password_manager, input_validator, rate_limiter, 
        session_manager, security_logger, two_factor_auth,
        get_client_ip, check_login_attempts, log_login_attempt,
        initialize_security_database, rate_limit_decorator,
        require_authentication, require_role
    )
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    st.error("⚠️ Security fixes module not available. Running in fallback mode.")

# Page configuration
st.set_page_config(
    page_title="RoadReportNG - Secure",
    page_icon="🛣️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for clean UI
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1f77b4 0%, #ff7f0e 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
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
    .warning-box {
        background-color: #fff3cd;
        border: 2px solid #856404;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        color: #856404;
    }
</style>
""", unsafe_allow_html=True)

# Initialize security database
if SECURITY_AVAILABLE:
    initialize_security_database()

# Database setup with security
def init_database():
    """Initialize SQLite database with enhanced security"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Users table with enhanced security
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                phone_number TEXT NOT NULL UNIQUE,
                email TEXT,
                role TEXT NOT NULL DEFAULT 'user',
                nin_or_passport TEXT,
                password_hash TEXT NOT NULL,
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                account_locked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0
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
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Database initialization error: {str(e)}")
        return False

# Secure user registration
def register_user_secure(user_data: dict) -> tuple[bool, str]:
    """Register a new user with enhanced security"""
    try:
        # Validate and sanitize all inputs
        if not SECURITY_AVAILABLE:
            return register_user_fallback(user_data)
        
        # Sanitize inputs
        full_name = input_validator.sanitize_input(user_data.get('full_name', ''))
        phone_number = input_validator.sanitize_input(user_data.get('phone_number', ''))
        email = input_validator.sanitize_input(user_data.get('email', ''))
        nin_or_passport = input_validator.sanitize_input(user_data.get('nin_or_passport', ''))
        password = user_data.get('password', '')
        
        # Validate inputs
        if not full_name or len(full_name) < 2:
            return False, "Full name must be at least 2 characters long"
        
        if not input_validator.validate_phone(phone_number):
            return False, "Invalid Nigerian phone number format"
        
        if email and not input_validator.validate_email(email):
            return False, "Invalid email format"
        
        if nin_or_passport and not input_validator.validate_nin(nin_or_passport):
            return False, "NIN must be exactly 11 digits if provided"
        
        # Validate password strength
        is_strong, password_message = password_manager.validate_password_strength(password)
        if not is_strong:
            return False, f"Password validation failed: {password_message}"
        
        # Check if user already exists
        if check_user_exists_secure(email, phone_number, nin_or_passport):
            return False, "User with this email or phone number already exists"
        
        # Hash password securely
        hashed_password = password_manager.hash_password(password)
        
        # Save to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport, password_hash
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (full_name, phone_number, email, user_data.get('role', 'user'), 
              nin_or_passport if nin_or_passport else None, hashed_password))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log security event
        security_logger.log_security_event(
            "user_registration", 
            f"New user registered: {full_name}",
            "INFO",
            user_id=user_id
        )
        
        return True, "Registration successful! You can now log in."
        
    except Exception as e:
        security_logger.log_security_event(
            "registration_failed", 
            f"Registration failed: {str(e)}", 
            "ERROR"
        )
        return False, f"Registration failed: {str(e)}"

def register_user_fallback(user_data: dict) -> tuple[bool, str]:
    """Fallback registration without security module"""
    try:
        # Basic validation
        if not user_data.get('full_name') or len(user_data['full_name']) < 2:
            return False, "Full name must be at least 2 characters long"
        
        if not user_data.get('phone_number'):
            return False, "Phone number is required"
        
        # Basic password validation
        password = user_data.get('password', '')
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        # Hash password (basic)
        import hashlib
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        # Save to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport, password_hash
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_data['full_name'],
            user_data['phone_number'],
            user_data.get('email'),
            user_data.get('role', 'user'),
            user_data.get('nin_or_passport'),
            hashed_password
        ))
        
        conn.commit()
        conn.close()
        
        return True, "Registration successful! You can now log in."
        
    except Exception as e:
        return False, f"Registration failed: {str(e)}"

# Secure user authentication
def authenticate_user_secure(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate user with enhanced security"""
    try:
        if not SECURITY_AVAILABLE:
            return authenticate_user_fallback(identifier, password)
        
        user_ip = get_client_ip()
        
        # Check login attempts
        if not check_login_attempts(identifier):
            lockout_duration = 30  # minutes
            return False, {}, f"Account temporarily locked due to too many failed attempts. Please wait {lockout_duration} minutes before trying again."
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find user by email or phone
        cursor.execute('''
            SELECT id, full_name, phone_number, email, role, nin_or_passport, password_hash, 
                   two_factor_enabled, account_locked, created_at, last_login, failed_attempts
            FROM users 
            WHERE (email = ? OR phone_number = ?)
        ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            log_login_attempt(identifier, False, "User not found")
            return False, {}, "Invalid email/phone or password"
        
        user_id, full_name, phone, email, role, nin_or_passport, password_hash, two_factor_enabled, account_locked, created_at, last_login, failed_attempts = user
        
        # Check if account is locked
        if account_locked:
            conn.close()
            log_login_attempt(identifier, False, "Account locked")
            return False, {}, "Account is locked. Please contact administrator."
        
        # Verify password
        if not password_manager.verify_password(password, password_hash):
            conn.close()
            log_login_attempt(identifier, False, "Invalid password")
            return False, {}, "Invalid email/phone or password"
        
        # Update last login and reset failed attempts
        cursor.execute('''
            UPDATE users SET last_login = ?, failed_attempts = 0 
            WHERE id = ?
        ''', (datetime.now().isoformat(), user_id))
        
        conn.commit()
        conn.close()
        
        user_data = {
            'id': user_id,
            'full_name': full_name,
            'email': email,
            'phone': phone,
            'role': role,
            'login_time': datetime.now().isoformat()
        }
        
        # Create secure session
        session_id = session_manager.create_session(user_data)
        
        # Log successful login
        log_login_attempt(identifier, True)
        security_logger.log_security_event(
            "login_success", 
            f"Successful login for user {full_name}", 
            "INFO",
            user_id=user_id,
            ip_address=user_ip
        )
        
        return True, user_data, session_id
        
    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        return False, {}, f"Authentication error: {str(e)}"

def authenticate_user_fallback(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Fallback authentication without security module"""
    try:
        import hashlib
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, full_name, phone_number, email, role, nin_or_passport, password_hash, 
                   two_factor_enabled, account_locked, created_at, last_login, failed_attempts
            FROM users 
            WHERE (email = ? OR phone_number = ?)
        ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False, {}, "Invalid email/phone or password"
        
        user_id, full_name, phone, email, role, nin_or_passport, password_hash, two_factor_enabled, account_locked, created_at, last_login, failed_attempts = user
        
        # Verify password (basic)
        if hashlib.sha256(password.encode('utf-8')).hexdigest() != password_hash:
            conn.close()
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
        
        return True, user_data, "fallback_session"
        
    except Exception as e:
        return False, {}, f"Authentication error: {str(e)}"

def check_user_exists_secure(email: str = None, phone: str = None, nin: str = None) -> bool:
    """Check if user already exists with input validation"""
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
        
        if nin and nin.strip():
            cursor.execute('SELECT id FROM users WHERE nin_or_passport = ?', (nin,))
            if cursor.fetchone():
                conn.close()
                return True
        
        conn.close()
        return False
    except Exception:
        return False

# Secure report submission
@rate_limit_decorator(max_requests=10, window_seconds=300)  # 10 reports per 5 minutes
def save_risk_report_secure(report_data: dict) -> tuple[bool, str]:
    """Save a new risk report with enhanced security"""
    try:
        # Validate and sanitize inputs
        if not SECURITY_AVAILABLE:
            return save_risk_report_fallback(report_data)
        
        risk_type = input_validator.sanitize_input(report_data.get('risk_type', ''))
        description = input_validator.sanitize_input(report_data.get('description', ''), max_length=1000)
        location = input_validator.sanitize_input(report_data.get('location', ''))
        
        if not risk_type or not description or not location:
            return False, "All required fields must be provided"
        
        # Validate file uploads if present
        if 'voice_file' in report_data and report_data['voice_file']:
            is_valid, message = input_validator.validate_file_upload(report_data['voice_file'])
            if not is_valid:
                return False, f"Voice file validation failed: {message}"
        
        if 'image_file' in report_data and report_data['image_file']:
            is_valid, message = input_validator.validate_file_upload(report_data['image_file'])
            if not is_valid:
                return False, f"Image file validation failed: {message}"
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO risk_reports (
                user_id, risk_type, description, location, latitude, longitude,
                voice_file_path, image_file_path, source_type, source_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_data['user_id'],
            risk_type,
            description,
            location,
            report_data.get('latitude'),
            report_data.get('longitude'),
            report_data.get('voice_file_path'),
            report_data.get('image_file_path'),
            report_data.get('source_type', 'user'),
            report_data.get('source_url')
        ))
        
        conn.commit()
        conn.close()
        
        # Log security event
        security_logger.log_security_event(
            "report_submitted",
            f"Risk report submitted: {risk_type} at {location}",
            "INFO",
            user_id=report_data['user_id']
        )
        
        return True, "Risk report submitted successfully!"
        
    except Exception as e:
        security_logger.log_security_event(
            "report_submission_failed",
            f"Report submission failed: {str(e)}",
            "ERROR"
        )
        return False, f"Report submission failed: {str(e)}"

def save_risk_report_fallback(report_data: dict) -> tuple[bool, str]:
    """Fallback report submission without security module"""
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
        return False, "Report submission failed"

# Initialize database
init_database()

# Main application
def main():
    st.markdown('<div class="main-header"><h1>🛣️ Road Report Nigeria - SECURE</h1><p>Enhanced Road Status System with Critical Security Fixes</p></div>', unsafe_allow_html=True)
    
    # Security status indicator
    if SECURITY_AVAILABLE:
        st.success("🔒 Security fixes are active and protecting your application")
    else:
        st.warning("⚠️ Running in fallback mode - security features limited")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    
    # Check authentication
    if 'session_id' in st.session_state and SECURITY_AVAILABLE:
        # User is logged in with secure session
        session_data = session_manager.get_session(st.session_state.session_id)
        if session_data and session_manager.validate_session(st.session_state.session_id):
            st.sidebar.success(f"👋 Welcome, {session_data['full_name']}!")
            st.sidebar.info(f"Role: {session_data['role']}")
            
            page = st.sidebar.selectbox(
                "Choose a page:",
                ["Dashboard", "Submit Report", "View Reports", "Security Settings", "Logout"]
            )
            
            if page == "Dashboard":
                show_dashboard_secure(session_data)
            elif page == "Submit Report":
                show_submit_report_secure(session_data)
            elif page == "View Reports":
                show_view_reports_secure(session_data)
            elif page == "Security Settings":
                show_security_settings_secure(session_data)
            elif page == "Logout":
                session_manager.delete_session(st.session_state.session_id)
                del st.session_state.session_id
                st.success("✅ Successfully logged out!")
                st.rerun()
        else:
            # Session expired
            if 'session_id' in st.session_state:
                del st.session_state.session_id
            st.sidebar.warning("Session expired. Please log in again.")
            show_login_page_secure()
    else:
        # User is not logged in
        st.sidebar.info("🔐 Please log in to access the system")
        
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["Login", "Register", "About"]
        )
        
        if page == "Login":
            show_login_page_secure()
        elif page == "Register":
            show_registration_page_secure()
        elif page == "About":
            show_about_page()

def show_login_page_secure():
    st.header("🔐 Secure Login")
    
    with st.form("secure_login_form"):
        identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        # 2FA if available
        if SECURITY_AVAILABLE and two_factor_auth.TOTP_AVAILABLE:
            st.subheader("🔒 Two-Factor Authentication")
            otp = st.text_input("Enter OTP (if enabled)", placeholder="6-digit code", max_chars=6)
        else:
            otp = None
        
        submit = st.form_submit_button("🔐 Login", type="primary")
        
        if submit:
            if not identifier or not password:
                st.error("❌ Please fill in all required fields")
                return
            
            # Show loading
            with st.spinner("🔐 Authenticating securely..."):
                time.sleep(1)  # Simulate authentication delay
                success, user_data, session_id = authenticate_user_secure(identifier, password)
            
            if success:
                # Store session ID
                st.session_state.session_id = session_id
                st.success(f"✅ Login successful!")
                st.balloons()
                time.sleep(1)
                st.rerun()
            else:
                st.error(f"❌ {user_data}")  # user_data contains error message here

def show_registration_page_secure():
    st.header("📝 Secure Registration")
    
    with st.form("secure_registration_form"):
        st.subheader("Personal Information")
        full_name = st.text_input("Full Name *", placeholder="Enter your full name")
        phone_number = st.text_input("Phone Number *", placeholder="+2348012345678")
        email = st.text_input("Email (Optional)", placeholder="your.email@example.com")
        
        st.subheader("Role & Identification")
        role = st.selectbox("Role *", ["user", "driver", "admin"])
        nin_or_passport = st.text_input("NIN (Optional - 11 digits)", placeholder="12345678901")
        
        st.subheader("Security")
        password = st.text_input("Password *", type="password", placeholder="Create a strong password")
        confirm_password = st.text_input("Confirm Password *", type="password", placeholder="Confirm your password")
        
        submit = st.form_submit_button("Register Securely", type="primary")
        
        if submit:
            # Basic validation
            if not all([full_name, phone_number, role, password, confirm_password]):
                st.error("Please fill in all required fields (marked with *)")
                return
            
            if password != confirm_password:
                st.error("Passwords do not match")
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
            
            success, message = register_user_secure(user_data)
            
            if success:
                st.success(message)
                st.info("You can now login with your credentials.")
            else:
                st.error(message)

def show_dashboard_secure(session_data: dict):
    st.header("📊 Secure Dashboard")
    
    st.markdown(f"""
    <div class="success-box">
        <h3>Welcome back, {session_data['full_name']}!</h3>
        <p><strong>Role:</strong> {session_data['role']}</p>
        <p><strong>Email:</strong> {session_data['email'] or 'Not provided'}</p>
        <p><strong>Phone:</strong> {session_data['phone']}</p>
        <p><strong>Security Status:</strong> 🔒 Enhanced security active</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Security features status
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔒 Security Features")
        st.success("✅ Secure password hashing (bcrypt)")
        st.success("✅ Input validation & sanitization")
        st.success("✅ Rate limiting active")
        st.success("✅ Session management")
        st.success("✅ Security logging")
    
    with col2:
        st.markdown("### 📊 Quick Stats")
        st.metric("Total Reports", "0")  # Placeholder
        st.metric("Pending Reports", "0")
        st.metric("Verified Reports", "0")
        st.metric("Security Events", "0")

def show_submit_report_secure(session_data: dict):
    st.header("🚨 Submit Secure Risk Report")
    
    st.warning("""
    🚨 **SECURITY NOTICE**: All reports are validated and monitored for accuracy. 
    False reports may result in account suspension.
    """)
    
    with st.form("secure_risk_report_form"):
        st.subheader("Risk Information")
        
        risk_types = ["Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        risk_type = st.selectbox("Risk Type *", risk_types)
        
        if risk_type == "Other":
            risk_type = st.text_input("Specify Risk Type *", placeholder="Enter the specific risk type")
        
        description = st.text_area("Description *", placeholder="Provide detailed description of the risk...", height=100)
        
        st.subheader("Location Information")
        col1, col2 = st.columns(2)
        with col1:
            latitude = st.number_input("Latitude", value=6.5244, format="%.4f")
        with col2:
            longitude = st.number_input("Longitude", value=3.3792, format="%.4f")
        
        location = st.text_input("Location Description *", placeholder="e.g., Lagos-Ibadan Expressway, Lagos State")
        
        st.subheader("Additional Information")
        voice_file = st.file_uploader("Voice Recording (Optional)", type=['wav', 'mp3'])
        image_file = st.file_uploader("Image (Optional)", type=['jpg', 'jpeg', 'png'])
        
        submit = st.form_submit_button("Submit Secure Report", type="primary")
        
        if submit:
            # Validation
            if not risk_type or not description or not location:
                st.error("Please fill in all required fields")
                return
            
            # Prepare report data
            report_data = {
                'user_id': session_data['id'],
                'risk_type': risk_type,
                'description': description,
                'location': location,
                'latitude': latitude,
                'longitude': longitude,
                'voice_file': voice_file,
                'image_file': image_file
            }
            
            # Submit report
            success, message = save_risk_report_secure(report_data)
            
            if success:
                st.success(message)
                st.info("Your report has been submitted and is pending verification.")
            else:
                st.error(message)

def show_view_reports_secure(session_data: dict):
    st.header("📊 View Reports (Secure)")
    
    # Placeholder for reports display
    st.info("Reports will be displayed here with enhanced security validation.")
    
    # Example of secure data display
    st.markdown("### 🔒 Security Features Applied")
    st.success("✅ Input sanitization prevents XSS attacks")
    st.success("✅ Rate limiting prevents abuse")
    st.success("✅ Session validation ensures authorized access")
    st.success("✅ SQL injection protection active")

def show_security_settings_secure(session_data: dict):
    st.header("🔒 Security Settings")
    
    st.markdown("### Current Security Status")
    st.success("✅ Enhanced security is active")
    st.success("✅ Password hashing: bcrypt")
    st.success("✅ Session management: Secure")
    st.success("✅ Rate limiting: Active")
    st.success("✅ Input validation: Active")
    
    # Security recommendations
    st.markdown("### 🔐 Security Recommendations")
    st.info("""
    1. **Use a strong password** with uppercase, lowercase, numbers, and special characters
    2. **Enable 2FA** if available for additional security
    3. **Log out** when using shared computers
    4. **Report suspicious activity** immediately
    5. **Keep your contact information updated**
    """)

def show_about_page():
    st.header("ℹ️ About - Secure Version")
    
    st.markdown("""
    ## 🔒 Enhanced Security Features
    
    This version of the Nigerian Road Risk Reporter includes critical security fixes:
    
    ### ✅ Implemented Security Measures
    
    - **Secure Password Hashing**: Using bcrypt with salt
    - **Input Validation**: Comprehensive sanitization and validation
    - **Rate Limiting**: Prevents abuse and brute force attacks
    - **Session Management**: Secure session handling
    - **SQL Injection Protection**: Parameterized queries
    - **Security Logging**: Comprehensive audit trails
    - **File Upload Security**: MIME type and size validation
    
    ### 🛡️ Additional Protections
    
    - Account lockout after failed attempts
    - IP-based rate limiting
    - XSS protection through input sanitization
    - Secure session management
    - Comprehensive error handling
    
    ### 📊 Security Monitoring
    
    All security events are logged and monitored for suspicious activity.
    """)

if __name__ == "__main__":
    main() 