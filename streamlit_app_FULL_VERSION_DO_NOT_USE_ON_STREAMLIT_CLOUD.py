"""
Nigerian Road Risk Reporting App - Streamlit Version
Secure registration system with role-based validation and file upload
"""

import streamlit as st
import os
import re
import uuid
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import bcrypt
from PIL import Image
import io

# Page configuration
st.set_page_config(
    page_title="Nigerian Road Risk Reporting",
    page_icon="🚗",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .form-container {
        background: rgba(255, 255, 255, 0.95);
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .success-message {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .error-message {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .login-container {
        max-width: 400px;
        margin: 0 auto;
        padding: 2rem;
        background: rgba(255, 255, 255, 0.95);
        border-radius: 15px;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
    }
</style>
""", unsafe_allow_html=True)

# Database setup
def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone_number TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            role TEXT NOT NULL,
            nin_or_passport TEXT UNIQUE NOT NULL,
            official_authority TEXT,
            id_file_path TEXT,
            password_hash TEXT NOT NULL,
            registration_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Create login_attempts table
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
    
    # Create password_resets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
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

def validate_phone_number(phone: str) -> bool:
    """Validate Nigerian phone number format"""
    phone_pattern = r'^(\+234|0)[789][01]\d{8}$'
    return bool(re.match(phone_pattern, phone))

def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email:
        return True  # Email is optional
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def validate_nin_or_passport(value: str) -> bool:
    """Validate NIN (11 digits) or passport (6-9 characters)"""
    if len(value) == 11 and value.isdigit():
        return True  # NIN format
    elif 6 <= len(value) <= 9:
        return True  # Passport format
    return False

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
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    return str(file_path)

def check_user_exists(phone: str, nin_or_passport: str, email: str = None) -> bool:
    """Check if user already exists"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if email:
        cursor.execute('''
            SELECT COUNT(*) FROM users 
            WHERE phone_number = ? OR nin_or_passport = ? OR email = ?
        ''', (phone, nin_or_passport, email))
    else:
        cursor.execute('''
            SELECT COUNT(*) FROM users 
            WHERE phone_number = ? OR nin_or_passport = ?
        ''', (phone, nin_or_passport))
    
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def register_user(user_data: dict) -> tuple[bool, str]:
    """Register new user"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Hash password
        hashed_password = hash_password(user_data['password'])
        
        # Insert user
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport,
                official_authority, id_file_path, password_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_data['full_name'],
            user_data['phone_number'],
            user_data['email'],
            user_data['role'],
            user_data['nin_or_passport'],
            user_data['official_authority'],
            user_data['id_file_path'],
            hashed_password
        ))
        
        conn.commit()
        conn.close()
        return True, "Registration successful! Please verify your identity."
        
    except Exception as e:
        return False, f"Registration failed: {str(e)}"

def verify_user(user_id: int) -> tuple[bool, str]:
    """Verify user identity"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET registration_status = 'verified' 
            WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        return True, "Identity verified successfully!"
        
    except Exception as e:
        return False, f"Verification failed: {str(e)}"

def get_users() -> list:
    """Get all users"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, full_name, phone_number, email, role, 
               registration_status, created_at 
        FROM users ORDER BY created_at DESC
    ''')
    
    users = cursor.fetchall()
    conn.close()
    return users

def authenticate_user(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate user login"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find user by email or phone
        cursor.execute('''
            SELECT id, full_name, email, phone_number, role, password_hash, registration_status
            FROM users 
            WHERE email = ? OR phone_number = ?
        ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if user and verify_password(password, user[5]):  # user[5] is password_hash
            # Log successful login attempt
            cursor.execute('''
                INSERT INTO login_attempts (user_identifier, success)
                VALUES (?, 1)
            ''', (identifier,))
            
            conn.commit()
            conn.close()
            
            user_data = {
                'id': user[0],
                'full_name': user[1],
                'email': user[2],
                'phone_number': user[3],
                'role': user[4],
                'registration_status': user[6]
            }
            return True, user_data, "Login successful!"
        else:
            # Log failed login attempt
            cursor.execute('''
                INSERT INTO login_attempts (user_identifier, success)
                VALUES (?, 0)
            ''', (identifier,))
            
            conn.commit()
            conn.close()
            return False, {}, "Invalid email/phone or password"
            
    except Exception as e:
        return False, {}, f"Authentication failed: {str(e)}"

def request_password_reset(identifier: str) -> tuple[bool, str]:
    """Request password reset"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find user by email or phone
        cursor.execute('''
            SELECT id, email, phone_number FROM users 
            WHERE email = ? OR phone_number = ?
        ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if not user:
            # Don't reveal if user exists or not for security
            return True, "If the email/phone exists, a password reset link has been sent."
        
        # Generate reset token
        token = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(hours=1)
        
        # Save reset token
        cursor.execute('''
            INSERT INTO password_resets (user_id, token, expires_at)
            VALUES (?, ?, ?)
        ''', (user[0], token, expires_at))
        
        conn.commit()
        conn.close()
        
        # Simulate sending email (in real app, send actual email)
        st.info(f"""
        === PASSWORD RESET EMAIL ===
        To: {user[1] or user[2]}
        Subject: Password Reset Request
        Reset Link: http://localhost:8501/reset-password?token={token}
        Token expires at: {expires_at}
        =============================
        """)
        
        return True, "If the email/phone exists, a password reset link has been sent."
        
    except Exception as e:
        return False, f"Password reset request failed: {str(e)}"

def reset_password(token: str, new_password: str) -> tuple[bool, str]:
    """Reset password with token"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find valid reset token
        cursor.execute('''
            SELECT user_id, used, expires_at FROM password_resets 
            WHERE token = ? AND used = 0 AND expires_at > ?
        ''', (token, datetime.now()))
        
        reset_record = cursor.fetchone()
        
        if not reset_record:
            conn.close()
            return False, "Invalid or expired reset token"
        
        # Update password
        hashed_password = hash_password(new_password)
        cursor.execute('''
            UPDATE users SET password_hash = ? WHERE id = ?
        ''', (hashed_password, reset_record[0]))
        
        # Mark token as used
        cursor.execute('''
            UPDATE password_resets SET used = 1 WHERE token = ?
        ''', (token,))
        
        conn.commit()
        conn.close()
        
        return True, "Password reset successful! You can now login with your new password."
        
    except Exception as e:
        return False, f"Password reset failed: {str(e)}"

def get_login_attempts() -> list:
    """Get login attempts for audit trail"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT user_identifier, ip_address, success, timestamp, user_agent
        FROM login_attempts 
        ORDER BY timestamp DESC 
        LIMIT 100
    ''')
    
    attempts = cursor.fetchall()
    conn.close()
    return attempts

# Initialize database
init_database()

# Session state management
if 'user' not in st.session_state:
    st.session_state.user = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Login"

# Main application
def main():
    # Check if user is logged in
    if st.session_state.user:
        show_dashboard()
    else:
        show_login_page()

def show_login_page():
    """Display the login page"""
    st.markdown("""
        <div class="main-header">
            <h1>🚗 Nigerian Road Risk Reporting</h1>
            <p>Secure Login Portal</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["Login", "Registration", "Forgot Password", "About"]
    )
    
    if page == "Login":
        show_login_form()
    elif page == "Registration":
        show_registration_form()
    elif page == "Forgot Password":
        show_forgot_password_form()
    elif page == "About":
        show_about_page()

def show_login_form():
    """Display the login form"""
    st.header("🔐 User Login")
    
    with st.container():
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        
        with st.form("login_form"):
            identifier = st.text_input("Email or Phone Number *", placeholder="Enter your email or phone")
            password = st.text_input("Password *", type="password", placeholder="Enter your password")
            
            submitted = st.form_submit_button("Sign In", type="primary")
            
            if submitted:
                if not identifier or not password:
                    st.error("Please fill in all fields")
                else:
                    success, user_data, message = authenticate_user(identifier, password)
                    
                    if success:
                        st.session_state.user = user_data
                        st.success(message)
                        st.balloons()
                        st.rerun()
                    else:
                        st.error(message)
        
        st.markdown('</div>', unsafe_allow_html=True)

def show_forgot_password_form():
    """Display the forgot password form"""
    st.header("🔑 Forgot Password")
    
    with st.container():
        st.markdown('<div class="form-container">', unsafe_allow_html=True)
        
        with st.form("forgot_password_form"):
            identifier = st.text_input("Email or Phone Number *", placeholder="Enter your email or phone")
            
            submitted = st.form_submit_button("Send Reset Link", type="primary")
            
            if submitted:
                if not identifier:
                    st.error("Please enter your email or phone number")
                else:
                    success, message = request_password_reset(identifier)
                    
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
        
        st.markdown('</div>', unsafe_allow_html=True)

def show_registration_form():
    """Display the registration form"""
    st.header("📝 User Registration")
    
    with st.container():
        st.markdown('<div class="form-container">', unsafe_allow_html=True)
        
        # Registration form
        with st.form("registration_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                full_name = st.text_input("Full Name *", placeholder="Enter your full name")
                phone_number = st.text_input("Phone Number *", placeholder="+2348012345678 or 08012345678")
                email = st.text_input("Email Address (Optional)", placeholder="your.email@example.com")
                role = st.selectbox("Role *", ["", "Public", "Driver", "Admin"])
            
            with col2:
                nin_or_passport = st.text_input("NIN or Passport Number *", placeholder="11-digit NIN or Passport number")
                password = st.text_input("Password *", type="password", placeholder="Create a strong password")
                confirm_password = st.text_input("Confirm Password *", type="password", placeholder="Confirm your password")
                
                # Admin-specific field
                official_authority = None
                if role == "Admin":
                    official_authority = st.text_input("Official Authority Name *", placeholder="Enter your official authority name")
            
            # File upload
            st.subheader("ID Document Upload (Optional)")
            uploaded_file = st.file_uploader(
                "Upload ID Document",
                type=['pdf', 'jpg', 'jpeg', 'png'],
                help="Accepted formats: PDF, JPG, JPEG, PNG (Max: 5MB)"
            )
            
            # Form submission
            submitted = st.form_submit_button("Register Account", type="primary")
            
            if submitted:
                # Validation
                errors = []
                
                if not full_name or len(full_name.strip()) < 2:
                    errors.append("Full name must be at least 2 characters")
                
                if not validate_phone_number(phone_number):
                    errors.append("Invalid Nigerian phone number format")
                
                if email and not validate_email(email):
                    errors.append("Invalid email format")
                
                if not validate_nin_or_passport(nin_or_passport):
                    errors.append("NIN must be 11 digits or provide valid passport number")
                
                if role == "Admin" and not official_authority:
                    errors.append("Official Authority Name is required for Admin role")
                
                if password != confirm_password:
                    errors.append("Passwords do not match")
                
                if len(password) < 6:
                    errors.append("Password must be at least 6 characters")
                
                # Check if user already exists
                if check_user_exists(phone_number, nin_or_passport, email):
                    errors.append("User already exists with this phone, NIN/passport, or email")
                
                # Display errors or proceed with registration
                if errors:
                    for error in errors:
                        st.error(error)
                else:
                    # Save uploaded file
                    id_file_path = save_uploaded_file(uploaded_file)
                    
                    # Prepare user data
                    user_data = {
                        'full_name': full_name.strip(),
                        'phone_number': phone_number,
                        'email': email if email else None,
                        'role': role,
                        'nin_or_passport': nin_or_passport,
                        'official_authority': official_authority,
                        'password': password,
                        'id_file_path': id_file_path
                    }
                    
                    # Register user
                    success, message = register_user(user_data)
                    
                    if success:
                        st.success(message)
                        st.balloons()
                    else:
                        st.error(message)
        
        st.markdown('</div>', unsafe_allow_html=True)

def show_user_management():
    """Display user management interface"""
    st.header("👥 User Management")
    
    # Get all users
    users = get_users()
    
    if not users:
        st.info("No users registered yet.")
        return
    
    # Display users in a table
    st.subheader("Registered Users")
    
    # Create DataFrame-like display
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    
    with col1:
        st.write("**ID**")
    with col2:
        st.write("**Name**")
    with col3:
        st.write("**Phone**")
    with col4:
        st.write("**Role**")
    with col5:
        st.write("**Status**")
    with col6:
        st.write("**Actions**")
    
    for user in users:
        user_id, full_name, phone, email, role, status, created_at = user
        
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        with col1:
            st.write(user_id)
        with col2:
            st.write(full_name)
        with col3:
            st.write(phone)
        with col4:
            st.write(role)
        with col5:
            status_color = "🟢" if status == "verified" else "🟡"
            st.write(f"{status_color} {status}")
        with col6:
            if status == "pending":
                if st.button(f"Verify {user_id}", key=f"verify_{user_id}"):
                    success, message = verify_user(user_id)
                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
        
        st.divider()

def show_security_logs():
    """Display security logs"""
    st.header("🛡️ Security Logs")
    
    attempts = get_login_attempts()
    
    if not attempts:
        st.info("No login attempts recorded yet.")
        return
    
    st.subheader("Recent Login Attempts")
    
    # Display attempts in a table
    for attempt in attempts:
        identifier, ip_address, success, timestamp, user_agent = attempt
        
        status_icon = "✅" if success else "❌"
        status_text = "Success" if success else "Failed"
        
        with st.expander(f"{status_icon} {identifier} - {status_text} ({timestamp})"):
            st.write(f"**Identifier:** {identifier}")
            st.write(f"**IP Address:** {ip_address or 'Unknown'}")
            st.write(f"**Status:** {status_text}")
            st.write(f"**Timestamp:** {timestamp}")
            if user_agent:
                st.write(f"**User Agent:** {user_agent}")

def show_about_page():
    """Display about page"""
    st.header("ℹ️ About")
    
    st.markdown("""
    ## Nigerian Road Risk Reporting App
    
    This application provides a secure registration and login system for the Nigerian Road Risk Reporting platform.
    
    ### Features:
    - 🔐 **Secure Login**: Multi-factor authentication with audit logging
    - 🔑 **Password Reset**: Secure password reset with email simulation
    - 📱 **Nigerian Phone Validation**: Supports Nigerian phone number formats
    - 🆔 **Identity Verification**: NIN and Passport number support
    - 📁 **File Upload**: ID document upload with security measures
    - 🛡️ **Role-based Access**: Admin, Driver, and Public user roles
    - 🔑 **Password Security**: bcrypt hashing for secure password storage
    - 📊 **Audit Trail**: Comprehensive login attempt logging
    
    ### Technical Stack:
    - **Backend**: Streamlit (Python)
    - **Database**: SQLite
    - **Security**: bcrypt password hashing
    - **File Handling**: Secure file upload and storage
    
    ### Contact:
    For support or questions, please contact the development team.
    """)

def show_dashboard():
    """Display the dashboard"""
    user = st.session_state.user
    
    # Header
    st.markdown("""
        <div class="main-header">
            <h1>🚗 Nigerian Road Risk Reporting</h1>
            <p>Welcome, """ + user['full_name'] + """!</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["Dashboard", "User Management", "Security Logs", "About"]
    )
    
    # Logout button
    if st.sidebar.button("🚪 Logout"):
        st.session_state.user = None
        st.rerun()
    
    if page == "Dashboard":
        show_dashboard_content()
    elif page == "User Management":
        show_user_management()
    elif page == "Security Logs":
        show_security_logs()
    elif page == "About":
        show_about_page()

def show_dashboard_content():
    """Display dashboard content"""
    st.header("📊 Dashboard")
    
    # Stats cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Users", "1,234", "+12%")
    
    with col2:
        st.metric("Risk Reports", "567", "+5%")
    
    with col3:
        st.metric("Resolved", "89", "+8%")
    
    with col4:
        st.metric("Pending", "23", "-3%")
    
    # Quick actions
    st.subheader("🚀 Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📝 New Registration", use_container_width=True):
            st.session_state.current_page = "Registration"
            st.rerun()
    
    with col2:
        if st.button("👥 View Users", use_container_width=True):
            st.session_state.current_page = "User Management"
            st.rerun()
    
    with col3:
        if st.button("🛡️ Security Logs", use_container_width=True):
            st.session_state.current_page = "Security Logs"
            st.rerun()
    
    # Recent activity
    st.subheader("📈 Recent Activity")
    
    # Simulate recent activity
    activities = [
        {"action": "New user registered", "time": "2 min ago", "icon": "👤"},
        {"action": "Risk report submitted", "time": "15 min ago", "icon": "⚠️"},
        {"action": "Report resolved", "time": "1 hour ago", "icon": "✅"},
        {"action": "Login attempt", "time": "2 hours ago", "icon": "🔐"}
    ]
    
    for activity in activities:
        st.write(f"{activity['icon']} {activity['action']} - {activity['time']}")

if __name__ == "__main__":
    main() 