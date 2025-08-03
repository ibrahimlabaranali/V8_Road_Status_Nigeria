#!/usr/bin/env python3
"""
Admin Login Module for Nigerian Road Risk Reporter
Secure admin authentication with 2FA and session management
"""

import streamlit as st
import sqlite3
import json
from db_setup import hash_password, verify_password, log_admin_action

# Page configuration
st.set_page_config(
    page_title="Admin Login - Road Risk Reporter",
    page_icon="🔐",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #dc3545, #6f42c1);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .login-container {
        max-width: 500px;
        margin: 0 auto;
        padding: 2rem;
        border: 1px solid #dee2e6;
        border-radius: 10px;
        background-color: #f8f9fa;
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
</style>
""", unsafe_allow_html=True)

def authenticate_admin(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate admin user"""
    try:
        conn = sqlite3.connect('db/users.db')
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

def create_demo_admin():
    """Create a demo admin user if none exists"""
    try:
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        
        # Check if admin exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "Admin"')
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create demo admin
            demo_admin = {
                'full_name': 'System Administrator',
                'phone_number': '+2348012345678',
                'email': 'admin@roadrisk.com',
                'role': 'Admin',
                'nin_or_passport': '12345678901',
                'password_hash': hash_password('admin123')
            }
            
            cursor.execute('''
                INSERT INTO users (full_name, phone_number, email, role, nin_or_passport, password_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                demo_admin['full_name'],
                demo_admin['phone_number'],
                demo_admin['email'],
                demo_admin['role'],
                demo_admin['nin_or_passport'],
                demo_admin['password_hash']
            ))
            
            conn.commit()
            st.success("Demo admin created! Email: admin@roadrisk.com, Password: admin123")
        
        conn.close()
    except Exception as e:
        st.error(f"Error creating demo admin: {str(e)}")

def main():
    st.markdown('<div class="main-header"><h1>🔐 Admin Login</h1><p>Nigerian Road Risk Reporter - Administrative Access</p></div>', unsafe_allow_html=True)
    
    # Check if already logged in
    if st.session_state.get("admin_logged_in"):
        st.success("You are already logged in as admin!")
        st.info(f"Welcome back, {st.session_state.admin_user['full_name']}")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📊 Go to Admin Dashboard", type="primary"):
                st.session_state.admin_page = "dashboard"
                st.rerun()
        with col2:
            if st.button("🚪 Logout", type="secondary"):
                st.session_state.admin_logged_in = False
                st.session_state.admin_user = None
                st.rerun()
        return
    
    # Create demo admin if needed
    create_demo_admin()
    
    # Login form
    with st.container():
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        
        st.subheader("🔐 Administrative Access")
        st.info("Enter your admin credentials to access the administrative panel.")
        
        with st.form("admin_login_form"):
            identifier = st.text_input(
                "Email or Phone Number",
                placeholder="admin@roadrisk.com or +2348012345678",
                help="Enter your registered email or phone number"
            )
            
            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password",
                help="Enter your admin password"
            )
            
            # 2FA simulation
            st.subheader("🔒 Two-Factor Authentication")
            st.info("For demo purposes, use OTP: 123456")
            otp = st.text_input(
                "Enter OTP",
                placeholder="123456",
                max_chars=6,
                help="Enter the 6-digit OTP from your authenticator app"
            )
            
            submit = st.form_submit_button("🔐 Login as Admin", type="primary")
            
            if submit:
                if not identifier or not password:
                    st.error("Please fill in all required fields")
                    return
                
                if not otp or otp != "123456":
                    st.error("Invalid OTP. Use 123456 for demo.")
                    return
                
                # Authenticate admin
                success, admin_data, message = authenticate_admin(identifier, password)
                
                if success:
                    # Set session state
                    st.session_state.admin_logged_in = True
                    st.session_state.admin_user = admin_data
                    
                    # Log successful login
                    log_admin_action(
                        admin_id=admin_data['id'],
                        admin_name=admin_data['full_name'],
                        admin_email=admin_data['email'],
                        action="ADMIN_LOGIN",
                        target_type="SYSTEM",
                        details=f"Successful admin login from {identifier}"
                    )
                    
                    st.success(f"🔐 {message}")
                    st.info(f"Welcome, {admin_data['full_name']}!")
                    
                    # Redirect to admin dashboard
                    st.markdown("""
                    <script>
                        setTimeout(function() {
                            window.location.href = "admin_dashboard.py";
                        }, 2000);
                    </script>
                    """, unsafe_allow_html=True)
                    
                    st.info("Redirecting to admin dashboard...")
                    st.rerun()
                else:
                    st.error(message)
                    
                    # Log failed login attempt
                    log_admin_action(
                        admin_id=0,
                        admin_name="Unknown",
                        admin_email=identifier if '@' in identifier else "Unknown",
                        action="FAILED_LOGIN",
                        target_type="SYSTEM",
                        details=f"Failed login attempt from {identifier}"
                    )
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Demo credentials
    st.subheader("📋 Demo Credentials")
    st.info("""
    **For testing purposes:**
    - **Email:** admin@roadrisk.com
    - **Phone:** +2348012345678
    - **Password:** admin123
    - **OTP:** 123456
    """)
    
    # Security notice
    st.subheader("🛡️ Security Notice")
    st.warning("""
    - This is a demo system with simplified security
    - In production, use strong passwords and real 2FA
    - All login attempts are logged for security monitoring
    - Admin actions are tracked for audit purposes
    """)

if __name__ == "__main__":
    main() 