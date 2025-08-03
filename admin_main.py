#!/usr/bin/env python3
"""
Main Entry Point for Nigerian Road Risk Reporter Admin System
Redirects to admin login or dashboard based on session state
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
</style>
""", unsafe_allow_html=True)

def main():
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
                st.switch_page("admin_dashboard.py")
        
        with col2:
            if st.button("⚙️ Config Panel", type="secondary"):
                st.switch_page("admin_config_panel.py")
        
        with col3:
            if st.button("👍 Community Validation", type="secondary"):
                st.switch_page("community_validation.py")
        
        with col4:
            if st.button("📊 View Logs", type="secondary"):
                st.switch_page("admin_logs.py")
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Logout option
        if st.button("🚪 Logout", type="secondary"):
            st.session_state.admin_logged_in = False
            st.session_state.admin_user = None
            st.rerun()
    
    else:
        st.markdown('<div class="welcome-card">', unsafe_allow_html=True)
        st.subheader("🔐 Administrative Access Required")
        st.info("Please login to access the administrative control panel.")
        
        if st.button("🔐 Login as Admin", type="primary"):
            st.switch_page("admin_login.py")
        
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

if __name__ == "__main__":
    main() 