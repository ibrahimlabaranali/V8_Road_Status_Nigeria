#!/usr/bin/env python3
"""
Main Entry Point for Nigerian Road Risk Reporter Admin System
Unified admin interface with session state navigation
"""

import streamlit as st
from db_setup import init_databases

# Page configuration
st.set_page_config(
    page_title="Admin System - Road Risk Reporter",
    page_icon="🔐",
    layout="wide"
)

# Initialize databases
init_databases()

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
    .welcome-card {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
        margin: 2rem 0;
    }
    .nav-button {
        background-color: #007bff;
        color: white;
        padding: 10px 20px;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        margin: 5px;
    }
    .nav-button:hover {
        background-color: #0056b3;
    }
</style>
""", unsafe_allow_html=True)

def show_login_page():
    """Show admin login page"""
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
    
    # Import admin login functions
    try:
        from admin_login import create_demo_admin, authenticate_admin, log_admin_action
    except ImportError:
        st.error("Admin login module not found. Please ensure all admin files are uploaded.")
        return
    
    # Create demo admin if needed
    create_demo_admin()
    
    # Login form
    with st.container():
        st.markdown('<div class="welcome-card">', unsafe_allow_html=True)
        
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
                placeholder="Enter your admin password",
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
                    st.session_state.admin_page = "dashboard"
                    
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

def show_dashboard():
    """Show admin dashboard"""
    try:
        from admin_dashboard import main as dashboard_main
        dashboard_main()
    except ImportError:
        st.error("Admin dashboard module not found. Please ensure all admin files are uploaded.")
        st.button("🔙 Back to Main", on_click=lambda: setattr(st.session_state, 'admin_page', 'main'))

def show_config_panel():
    """Show admin config panel"""
    try:
        from admin_config_panel import main as config_main
        config_main()
    except ImportError:
        st.error("Admin config panel module not found. Please ensure all admin files are uploaded.")
        st.button("🔙 Back to Main", on_click=lambda: setattr(st.session_state, 'admin_page', 'main'))

def show_community_validation():
    """Show community validation"""
    try:
        from community_validation import main as community_main
        community_main()
    except ImportError:
        st.error("Community validation module not found. Please ensure all admin files are uploaded.")
        st.button("🔙 Back to Main", on_click=lambda: setattr(st.session_state, 'admin_page', 'main'))

def show_admin_logs():
    """Show admin logs"""
    try:
        from admin_logs import main as logs_main
        logs_main()
    except ImportError:
        st.error("Admin logs module not found. Please ensure all admin files are uploaded.")
        st.button("🔙 Back to Main", on_click=lambda: setattr(st.session_state, 'admin_page', 'main'))

def show_main_page():
    """Show main admin page"""
    st.markdown('<div class="main-header"><h1>🔐 Nigerian Road Risk Reporter</h1><p>Administrative Control System</p></div>', unsafe_allow_html=True)
    
    # Check if admin is logged in
    if st.session_state.get("admin_logged_in"):
        admin_user = st.session_state.admin_user
        
        st.markdown('<div class="welcome-card">', unsafe_allow_html=True)
        st.success(f"🔐 Welcome back, {admin_user['full_name']}!")
        st.info(f"Admin ID: {admin_user['id']} | Email: {admin_user['email']}")
        
        st.subheader("🚀 Quick Access")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📊 Admin Dashboard", type="primary"):
                st.session_state.admin_page = "dashboard"
                st.rerun()
        
        with col2:
            if st.button("⚙️ Config Panel", type="secondary"):
                st.session_state.admin_page = "config"
                st.rerun()
        
        with col3:
            if st.button("👍 Community Validation", type="secondary"):
                st.session_state.admin_page = "community"
                st.rerun()
        
        with col4:
            if st.button("📊 View Logs", type="secondary"):
                st.session_state.admin_page = "logs"
                st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Logout option
        if st.button("🚪 Logout", type="secondary"):
            st.session_state.admin_logged_in = False
            st.session_state.admin_user = None
            st.session_state.admin_page = "login"
            st.rerun()
    
    else:
        st.markdown('<div class="welcome-card">', unsafe_allow_html=True)
        st.subheader("🔐 Administrative Access Required")
        st.info("Please login to access the administrative control panel.")
        
        if st.button("🔐 Login as Admin", type="primary"):
            st.session_state.admin_page = "login"
            st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # System information
        st.subheader("📋 System Information")
        st.info("""
        **Nigerian Road Risk Reporter - Admin System**
        
        This modular administrative system provides:
        
        🔐 **Admin Login**: Secure authentication with 2FA
        📊 **Admin Dashboard**: Report statistics and moderation
        ⚙️ **Config Panel**: User management and system configuration
        👍 **Community Validation**: Upvote system and trust scoring
        📊 **Admin Logs**: Complete audit trail and action logging
        
        **Security Features:**
        - SHA256 password hashing
        - Session state management
        - Role-based access control
        - Comprehensive audit logging
        - 2FA simulation
        
        **Database Structure:**
        - `db/users.db`: User accounts and roles
        - `db/risk_reports.db`: Risk reports and status
        - `db/admin_logs.db`: Administrative audit trail
        - `db/upvotes.db`: Community validation tracking
        
        **Configuration:**
        - `config.json`: Risk types and advice templates
        - Modular design for easy deployment
        - Streamlit Cloud compatible
        """)
        
        # Demo credentials
        st.subheader("📋 Demo Credentials")
        st.warning("""
        **For testing purposes:**
        - **Email:** admin@roadrisk.com
        - **Phone:** +2348012345678
        - **Password:** admin123
        - **OTP:** 123456
        
        *These credentials will be created automatically on first run.*
        """)

def main():
    # Initialize session state
    if 'admin_page' not in st.session_state:
        st.session_state.admin_page = "main"
    
    # Navigation based on session state
    if st.session_state.admin_page == "login":
        show_login_page()
    elif st.session_state.admin_page == "dashboard":
        show_dashboard()
    elif st.session_state.admin_page == "config":
        show_config_panel()
    elif st.session_state.admin_page == "community":
        show_community_validation()
    elif st.session_state.admin_page == "logs":
        show_admin_logs()
    else:
        show_main_page()

if __name__ == "__main__":
    main() 