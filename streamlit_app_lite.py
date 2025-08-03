#!/usr/bin/env python3
"""
Nigerian Road Risk Reporting App - Lite Version
Streamlit Cloud Compatible - No Pydantic Dependencies
"""

import streamlit as st
import sqlite3
import bcrypt
import uuid
import re
from datetime import datetime, timedelta
from pathlib import Path
import os
from PIL import Image
import io

# Page configuration
st.set_page_config(
    page_title="Nigerian Road Risk Reporter - Lite",
    page_icon="🛣️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1f77b4, #ff7f0e);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Database setup
def init_database():
    """Initialize SQLite database with all required tables"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone_number TEXT NOT NULL UNIQUE,
            email TEXT UNIQUE,
            role TEXT NOT NULL,
            nin_or_passport TEXT NOT NULL UNIQUE,
            official_authority TEXT,
            id_file_path TEXT,
            password_hash TEXT NOT NULL,
            registration_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Login attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_identifier TEXT NOT NULL,
            ip_address TEXT,
            success BOOLEAN DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_agent TEXT
        )
    ''')
    
    # Password resets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Utility functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def validate_email(email: str) -> bool:
    """Simple email validation"""
    if not email:
        return True  # Email is optional
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone: str) -> bool:
    """Nigerian phone number validation"""
    # Remove spaces and special characters
    phone = re.sub(r'[^\d+]', '', phone)
    # Check if it starts with +234 or 0 and has correct length
    if phone.startswith('+234') and len(phone) == 14:
        return True
    elif phone.startswith('0') and len(phone) == 11:
        return True
    return False

def validate_nin(nin: str) -> bool:
    """NIN validation (11 digits)"""
    return nin.isdigit() and len(nin) == 11

def save_uploaded_file(uploaded_file) -> str:
    """Save uploaded file and return file path"""
    if uploaded_file is None:
        return None
    
    # Create uploads directory if it doesn't exist
    upload_dir = Path("uploads")
    upload_dir.mkdir(exist_ok=True)
    
    # Generate unique filename
    file_extension = Path(uploaded_file.name).suffix
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = upload_dir / unique_filename
    
    # Save file
    with open(file_path, "wb") as buffer:
        buffer.write(uploaded_file.getbuffer())
    
    return str(file_path)

def check_user_exists(email: str = None, phone: str = None, nin: str = None) -> bool:
    """Check if user already exists"""
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
    
    if nin:
        cursor.execute('SELECT id FROM users WHERE nin_or_passport = ?', (nin,))
        if cursor.fetchone():
            conn.close()
            return True
    
    conn.close()
    return False

def register_user(user_data: dict) -> tuple[bool, str]:
    """Register a new user"""
    try:
        # Validate required fields
        if not user_data.get('full_name') or len(user_data['full_name']) < 2:
            return False, "Full name must be at least 2 characters long"
        
        if not validate_phone(user_data['phone_number']):
            return False, "Invalid Nigerian phone number format"
        
        if user_data.get('email') and not validate_email(user_data['email']):
            return False, "Invalid email format"
        
        if not validate_nin(user_data['nin_or_passport']):
            return False, "NIN must be exactly 11 digits"
        
        if user_data['role'] == 'Admin' and not user_data.get('official_authority'):
            return False, "Official Authority Name is required for Admin role"
        
        # Check if user already exists
        if check_user_exists(
            email=user_data.get('email'),
            phone=user_data['phone_number'],
            nin=user_data['nin_or_passport']
        ):
            return False, "User with this email, phone, or NIN already exists"
        
        # Hash password
        hashed_password = hash_password(user_data['password'])
        
        # Save to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport,
                official_authority, id_file_path, password_hash, registration_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_data['full_name'],
            user_data['phone_number'],
            user_data.get('email'),
            user_data['role'],
            user_data['nin_or_passport'],
            user_data.get('official_authority'),
            user_data.get('id_file_path'),
            hashed_password,
            'pending'
        ))
        
        conn.commit()
        conn.close()
        
        return True, "Registration successful! Please wait for verification."
        
    except Exception as e:
        return False, f"Registration failed: {str(e)}"

def authenticate_user(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate user login"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find user by email or phone
        cursor.execute('''
            SELECT id, full_name, email, phone_number, role, password_hash, registration_status
            FROM users 
            WHERE (email = ? OR phone_number = ?) AND is_active = 1
        ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False, {}, "Invalid email/phone or password"
        
        user_id, full_name, email, phone, role, password_hash, status = user
        
        # Verify password
        if not verify_password(password, password_hash):
            conn.close()
            return False, {}, "Invalid email/phone or password"
        
        # Check if user is verified
        if status != 'verified':
            conn.close()
            return False, {}, "Account not yet verified. Please contact administrator."
        
        # Log successful login attempt
        cursor.execute('''
            INSERT INTO login_attempts (user_identifier, success)
            VALUES (?, 1)
        ''', (identifier,))
        
        conn.commit()
        conn.close()
        
        user_data = {
            'id': user_id,
            'full_name': full_name,
            'email': email,
            'phone': phone,
            'role': role
        }
        
        return True, user_data, "Login successful!"
        
    except Exception as e:
        return False, {}, f"Login failed: {str(e)}"

def request_password_reset(identifier: str) -> tuple[bool, str]:
    """Request password reset"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find user
        cursor.execute('SELECT id FROM users WHERE email = ? OR phone_number = ?', (identifier, identifier))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return True, "If the email/phone exists, a password reset link has been sent."
        
        user_id = user[0]
        
        # Generate reset token
        token = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(hours=1)
        
        # Save reset token
        cursor.execute('''
            INSERT INTO password_resets (user_id, token, expires_at)
            VALUES (?, ?, ?)
        ''', (user_id, token, expires_at))
        
        conn.commit()
        conn.close()
        
        # Simulate sending email (in real app, send actual email)
        st.info(f"📧 Password reset email would be sent to: {identifier}")
        st.info(f"🔗 Reset token: {token}")
        st.info(f"⏰ Token expires at: {expires_at}")
        
        return True, "If the email/phone exists, a password reset link has been sent."
        
    except Exception as e:
        return False, f"Password reset request failed: {str(e)}"

def reset_password(token: str, new_password: str) -> tuple[bool, str]:
    """Reset password using token"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find valid reset token
        cursor.execute('''
            SELECT user_id FROM password_resets 
            WHERE token = ? AND used = 0 AND expires_at > ?
        ''', (token, datetime.now()))
        
        reset_record = cursor.fetchone()
        
        if not reset_record:
            conn.close()
            return False, "Invalid or expired reset token"
        
        user_id = reset_record[0]
        
        # Update password
        hashed_password = hash_password(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_password, user_id))
        
        # Mark token as used
        cursor.execute('UPDATE password_resets SET used = 1 WHERE token = ?', (token,))
        
        conn.commit()
        conn.close()
        
        return True, "Password reset successful! You can now login with your new password."
        
    except Exception as e:
        return False, f"Password reset failed: {str(e)}"

def get_login_attempts() -> list:
    """Get recent login attempts for audit"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_identifier, success, timestamp 
            FROM login_attempts 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        
        attempts = cursor.fetchall()
        conn.close()
        
        return attempts
        
    except Exception as e:
        return []

# Initialize database
init_database()

# Session state management
if 'user' not in st.session_state:
    st.session_state.user = None

# Main application
def main():
    st.markdown('<div class="main-header"><h1>🛣️ Nigerian Road Risk Reporter - Lite</h1><p>Secure Road Status Reporting System</p></div>', unsafe_allow_html=True)
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    
    if st.session_state.user:
        # User is logged in
        st.sidebar.success(f"Welcome, {st.session_state.user['full_name']}!")
        st.sidebar.info(f"Role: {st.session_state.user['role']}")
        
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["Dashboard", "User Management", "Security Logs", "Logout"]
        )
        
        if page == "Dashboard":
            show_dashboard()
        elif page == "User Management":
            show_user_management()
        elif page == "Security Logs":
            show_security_logs()
        elif page == "Logout":
            st.session_state.user = None
            st.rerun()
    else:
        # User is not logged in
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["Login", "Register", "Forgot Password", "About"]
        )
        
        if page == "Login":
            show_login_page()
        elif page == "Register":
            show_registration_page()
        elif page == "Forgot Password":
            show_forgot_password_page()
        elif page == "About":
            show_about_page()

def show_login_page():
    st.header("🔐 Login")
    
    with st.form("login_form"):
        identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            submit = st.form_submit_button("Login", type="primary")
        with col2:
            if st.form_submit_button("Forgot Password?"):
                st.switch_page("Forgot Password")
        
        if submit:
            if not identifier or not password:
                st.error("Please fill in all fields")
                return
            
            success, user_data, message = authenticate_user(identifier, password)
            
            if success:
                st.session_state.user = user_data
                st.success(message)
                st.rerun()
            else:
                st.error(message)

def show_registration_page():
    st.header("📝 User Registration")
    
    with st.form("registration_form"):
        st.subheader("Personal Information")
        full_name = st.text_input("Full Name", placeholder="Enter your full name")
        phone_number = st.text_input("Phone Number", placeholder="+2348012345678")
        email = st.text_input("Email (Optional)", placeholder="your.email@example.com")
        
        st.subheader("Role & Identification")
        role = st.selectbox("Role", ["Public", "Driver", "Admin"])
        nin_or_passport = st.text_input("NIN (11 digits)", placeholder="12345678901")
        
        # Conditional field for Admin role
        official_authority = None
        if role == "Admin":
            official_authority = st.text_input("Official Authority Name", placeholder="Enter your official authority name")
        
        st.subheader("Security")
        password = st.text_input("Password", type="password", placeholder="Create a strong password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
        
        st.subheader("Identity Verification")
        id_file = st.file_uploader(
            "Upload ID Document (PDF/JPEG/PNG, max 5MB)",
            type=['pdf', 'jpg', 'jpeg', 'png'],
            help="Upload a scanned copy of your ID for verification"
        )
        
        # CAPTCHA simulation
        st.subheader("Identity Verification")
        captcha_input = st.text_input("Enter the code: 1234", placeholder="Enter the verification code")
        
        submit = st.form_submit_button("Register", type="primary")
        
        if submit:
            # Validation
            if not all([full_name, phone_number, role, nin_or_passport, password, confirm_password]):
                st.error("Please fill in all required fields")
                return
            
            if password != confirm_password:
                st.error("Passwords do not match")
                return
            
            if len(password) < 8:
                st.error("Password must be at least 8 characters long")
                return
            
            if captcha_input != "1234":
                st.error("Invalid verification code")
                return
            
            if role == "Admin" and not official_authority:
                st.error("Official Authority Name is required for Admin role")
                return
            
            # Save uploaded file
            id_file_path = None
            if id_file:
                id_file_path = save_uploaded_file(id_file)
            
            # Register user
            user_data = {
                'full_name': full_name,
                'phone_number': phone_number,
                'email': email,
                'role': role,
                'nin_or_passport': nin_or_passport,
                'official_authority': official_authority,
                'password': password,
                'id_file_path': id_file_path
            }
            
            success, message = register_user(user_data)
            
            if success:
                st.success(message)
                st.info("Please wait for administrator verification before logging in.")
            else:
                st.error(message)

def show_forgot_password_page():
    st.header("🔑 Forgot Password")
    
    tab1, tab2 = st.tabs(["Request Reset", "Reset Password"])
    
    with tab1:
        with st.form("forgot_password_form"):
            identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone")
            submit = st.form_submit_button("Send Reset Link", type="primary")
            
            if submit:
                if not identifier:
                    st.error("Please enter your email or phone number")
                    return
                
                success, message = request_password_reset(identifier)
                
                if success:
                    st.success(message)
                else:
                    st.error(message)
    
    with tab2:
        with st.form("reset_password_form"):
            token = st.text_input("Reset Token", placeholder="Enter the reset token from your email")
            new_password = st.text_input("New Password", type="password", placeholder="Enter new password")
            confirm_password = st.text_input("Confirm New Password", type="password", placeholder="Confirm new password")
            submit = st.form_submit_button("Reset Password", type="primary")
            
            if submit:
                if not all([token, new_password, confirm_password]):
                    st.error("Please fill in all fields")
                    return
                
                if new_password != confirm_password:
                    st.error("Passwords do not match")
                    return
                
                if len(new_password) < 8:
                    st.error("Password must be at least 8 characters long")
                    return
                
                success, message = reset_password(token, new_password)
                
                if success:
                    st.success(message)
                else:
                    st.error(message)

def show_dashboard():
    st.header("📊 Dashboard")
    
    user = st.session_state.user
    
    # Welcome message
    st.markdown(f"""
    <div class="info-box">
        <h3>Welcome back, {user['full_name']}!</h3>
        <p><strong>Role:</strong> {user['role']}</p>
        <p><strong>Email:</strong> {user['email'] or 'Not provided'}</p>
        <p><strong>Phone:</strong> {user['phone']}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Dashboard content based on role
    if user['role'] == 'Admin':
        show_admin_dashboard()
    else:
        show_user_dashboard()

def show_admin_dashboard():
    st.subheader("🛠️ Admin Dashboard")
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Users", "25")
    with col2:
        st.metric("Pending Verifications", "3")
    with col3:
        st.metric("Active Reports", "12")
    with col4:
        st.metric("System Status", "🟢 Online")
    
    # Recent activity
    st.subheader("Recent Activity")
    st.info("Admin dashboard features would be implemented here")

def show_user_dashboard():
    st.subheader("👤 User Dashboard")
    
    # Quick actions
    st.subheader("Quick Actions")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📝 Report Road Issue", type="primary"):
            st.info("Road reporting feature would be implemented here")
    
    with col2:
        if st.button("🗺️ View Road Status"):
            st.info("Road status viewing feature would be implemented here")
    
    # Recent reports
    st.subheader("Your Recent Reports")
    st.info("Your recent road reports would appear here")

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
            SELECT id, full_name, email, phone_number, role, registration_status, created_at
            FROM users ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        
        if users:
            st.subheader("Registered Users")
            
            for user in users:
                user_id, full_name, email, phone, role, status, created_at = user
                
                with st.expander(f"{full_name} ({role})"):
                    st.write(f"**Email:** {email or 'Not provided'}")
                    st.write(f"**Phone:** {phone}")
                    st.write(f"**Status:** {status}")
                    st.write(f"**Registered:** {created_at}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if status == 'pending':
                            if st.button(f"Verify {full_name}", key=f"verify_{user_id}"):
                                # Verify user
                                conn = sqlite3.connect('users.db')
                                cursor = conn.cursor()
                                cursor.execute('UPDATE users SET registration_status = "verified" WHERE id = ?', (user_id,))
                                conn.commit()
                                conn.close()
                                st.success(f"{full_name} has been verified!")
                                st.rerun()
                    
                    with col2:
                        if st.button(f"Deactivate {full_name}", key=f"deactivate_{user_id}"):
                            # Deactivate user
                            conn = sqlite3.connect('users.db')
                            cursor = conn.cursor()
                            cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
                            conn.commit()
                            conn.close()
                            st.success(f"{full_name} has been deactivated!")
                            st.rerun()
        else:
            st.info("No users found")
            
    except Exception as e:
        st.error(f"Error loading users: {str(e)}")

def show_security_logs():
    st.header("🔒 Security Logs")
    
    if st.session_state.user['role'] != 'Admin':
        st.error("Access denied. Admin privileges required.")
        return
    
    # Login attempts
    attempts = get_login_attempts()
    
    if attempts:
        st.subheader("Recent Login Attempts")
        
        for attempt in attempts:
            user_identifier, success, timestamp = attempt
            status = "✅ Success" if success else "❌ Failed"
            
            st.write(f"**{user_identifier}** - {status} - {timestamp}")
    else:
        st.info("No login attempts found")

def show_about_page():
    st.header("ℹ️ About")
    
    st.markdown("""
    ## Nigerian Road Risk Reporter - Lite Version
    
    This is a streamlined version of the Nigerian Road Risk Reporting application, 
    designed for maximum compatibility with Streamlit Cloud deployment.
    
    ### Features:
    - ✅ User registration with validation
    - ✅ Secure login system
    - ✅ Password reset functionality
    - ✅ Role-based access control
    - ✅ File upload support
    - ✅ Audit logging
    - ✅ Admin user management
    
    ### Security Features:
    - 🔐 bcrypt password hashing
    - 📝 Login attempt logging
    - 🎫 Secure password reset tokens
    - 🛡️ Input validation and sanitization
    
    ### Tech Stack:
    - **Frontend:** Streamlit
    - **Backend:** Python
    - **Database:** SQLite
    - **Security:** bcrypt
    
    ### Compatibility:
    - ✅ Streamlit Cloud
    - ✅ Python 3.13+
    - ✅ No external dependencies that require compilation
    
    ---
    
    **Version:** Lite 1.0  
    **Last Updated:** August 2025  
    **Developer:** Dr Ibrahim L Ali
    """)

if __name__ == "__main__":
    main() 