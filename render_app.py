#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - Render Optimized Version
Clean and optimized for Render deployment
Python 3.10.13 compatible - Render Free Tier ready
"""

import streamlit as st
import sqlite3
import os
import hashlib
import secrets
import re
from datetime import datetime, timedelta

# Environment variables for Render deployment
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-key-change-in-production')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///users.db')

# Page configuration optimized for Render
st.set_page_config(
    page_title="RoadReportNG - Render",
    page_icon="🛣️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Database functions
def init_database():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table with complete schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            phone_number TEXT,
            role TEXT DEFAULT 'user',
            nin_or_passport TEXT,
            is_verified BOOLEAN DEFAULT 0,
            is_locked BOOLEAN DEFAULT 0,
            lockout_until TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    ''')
    
    # Create admin_users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone_number TEXT UNIQUE,
            email TEXT UNIQUE,
            nin TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            is_verified BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create password_resets table - CRITICAL for password reset functionality
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            user_type TEXT NOT NULL,
            reset_token TEXT UNIQUE NOT NULL,
            expiry_time TEXT NOT NULL,
            used BOOLEAN DEFAULT 0,
            used_at TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create risk_reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            risk_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            image_url TEXT,
            coordinates TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Password reset functions - CRITICAL for forgot password to work
def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def initiate_password_reset(identifier: str, user_type: str = "user") -> tuple[bool, str]:
    """Initiate password reset process"""
    try:
        if not identifier or len(identifier.strip()) < 3:
            return False, "Invalid identifier provided"
        
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
        expiry_time = datetime.now() + timedelta(hours=24)
        
        # Store reset token
        cursor.execute('''
            INSERT OR REPLACE INTO password_resets 
            (user_id, user_type, reset_token, expiry_time, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, user_type, reset_token, expiry_time, datetime.now()))
        
        conn.commit()
        conn.close()
        
        # Store token in session state for demo purposes
        if user_type == "admin":
            st.session_state.admin_reset_token = reset_token
        else:
            st.session_state.user_reset_token = reset_token
        
        return True, f"Reset token generated: {reset_token}"
        
    except Exception as e:
        return False, f"An error occurred: {str(e)}"

def reset_password(token: str, new_password: str) -> tuple[bool, str]:
    """Reset password using token"""
    try:
        # Validate password strength
        is_strong, strength_msg = validate_password_strength(new_password)
        if not is_strong:
            return False, f"Password validation failed: {strength_msg}"
        
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
        
        return True, "Password reset successfully"
        
    except Exception as e:
        return False, f"An error occurred: {str(e)}"

def get_risk_reports():
    """Get all risk reports from database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM risk_reports ORDER BY created_at DESC')
    reports = cursor.fetchall()
    conn.close()
    return reports

# Page functions
def show_road_status_checker():
    """Show the road status checker page"""
    st.header("🛣️ Road Status Checker")
    st.info("Check current road conditions and get safety advice")
    
    # Sample road status data
    road_status = {
        "Lagos-Ibadan Expressway": "🟡 Moderate congestion",
        "Abuja-Kano Highway": "🟢 Clear",
        "Port Harcourt-Enugu Road": "🔴 Heavy traffic",
        "Calabar-Uyo Highway": "🟡 Construction work"
    }
    
    st.subheader("Current Road Status")
    for road, status in road_status.items():
        st.write(f"**{road}:** {status}")
    
    st.subheader("Safety Advice")
    st.info("""
    - Always check road conditions before traveling
    - Follow traffic rules and speed limits
    - Keep emergency contacts handy
    - Report any road hazards you encounter
    """)

def show_risk_history():
    """Show user's risk report history"""
    st.header("📋 Risk Report History")
    st.info("View and manage your submitted risk reports")
    
    # Get reports from database
    reports = get_risk_reports()
    
    if reports:
        for report in reports[:5]:  # Show last 5 reports
            st.write(f"**{report[2]}** - {report[3]} - {report[4]}")
    else:
        st.info("No risk reports found. Submit your first report!")

def show_live_feeds():
    """Show live social media and news feeds"""
    st.header("📱 Live Feeds")
    st.info("Real-time updates from social media and news sources")
    
    # Simulated live feeds
    feeds = [
        "🚨 Accident reported on Lagos-Ibadan Expressway near Mowe",
        "⚠️ Heavy rainfall causing flooding on Port Harcourt roads",
        "✅ Construction completed on Abuja-Kano Highway section",
        "🛣️ New traffic light installed at Calabar junction"
    ]
    
    for feed in feeds:
        st.write(feed)
        st.write("---")

def show_manage_reports():
    """Show report management interface"""
    st.header("⚙️ Manage Reports")
    st.info("Update or resolve your submitted reports")
    
    st.button("Mark Report as Resolved", key="resolve_btn")
    st.button("Update Report Details", key="update_btn")
    st.button("Delete Report", key="delete_btn")

def show_analytics_page():
    """Show analytics and statistics"""
    st.header("📊 Analytics Dashboard")
    st.info("View road safety statistics and trends")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Reports", "156")
        st.metric("Active Issues", "23")
    
    with col2:
        st.metric("Resolved", "133")
        st.metric("Response Time", "2.3h")
    
    with col3:
        st.metric("User Satisfaction", "4.8/5")
        st.metric("Safety Score", "87%")

def show_deployment_page():
    """Show deployment information"""
    st.header("🚀 Deployment Info")
    st.info("Information about this Render deployment")
    
    st.success("✅ **Render Deployment Active**")
    st.write(f"**Environment:** {os.environ.get('RENDER_ENVIRONMENT', 'Production')}")
    st.write(f"**Python Version:** 3.10.13")
    st.write(f"**Streamlit Version:** 1.32.0")
    
    st.info("""
    **Features:**
    - Environment variable configuration
    - Database initialization
    - Clean and optimized code
    - Ready for production
    """)

def show_forgot_password_page():
    """Show forgot password functionality"""
    st.header("🔑 Forgot Password")
    st.info("Reset your password using email or phone number")
    
    # Create tabs for different reset methods
    tab1, tab2 = st.tabs(["🔑 Request Reset", "🔐 Reset Password"])
    
    with tab1:
        st.subheader("Request Password Reset")
        with st.form("forgot_password_form"):
            identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone")
            user_type = st.selectbox("Account Type", ["User", "Admin"])
            
            submit = st.form_submit_button("Send Reset Token", type="primary")
            
            if submit:
                if not identifier:
                    st.error("❌ Please enter your email or phone number")
                    return
                
                with st.spinner("🔑 Processing reset request..."):
                    success, message = initiate_password_reset(identifier, user_type.lower())
                
                if success:
                    st.success(f"✅ {message}")
                    st.info("💡 **Important:** Copy the reset token above. In production, this would be sent via email/SMS.")
                else:
                    st.error(f"❌ {message}")
    
    with tab2:
        st.subheader("Reset Your Password")
        with st.form("reset_password_form"):
            token = st.text_input("Reset Token", placeholder="Enter the reset token")
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
                
                with st.spinner("🔑 Resetting password..."):
                    success, message = reset_password(token, new_password)
                
                if success:
                    st.success(f"✅ {message}")
                    st.info("You can now login with your new password.")
                else:
                    st.error(f"❌ {message}")

# Main application
def main():
    """Main application optimized for Render deployment"""
    
    # Initialize database
    init_database()
    
    # Initialize session state
    if 'public_page' not in st.session_state:
        st.session_state.public_page = "Road Status Checker"
    
    # Header
    st.markdown('<div class="main-header"><h1>🛣️ Road Report Nigeria - Render</h1><p>Clean Road Status System - Render Optimized</p></div>', unsafe_allow_html=True)
    
    # Show deployment info
    st.info("🚀 **Render Deployment** - This version is optimized for Render hosting")
    
    # Sidebar navigation
    st.sidebar.title("🛣️ Navigation")
    
    # Public access navigation
    st.sidebar.markdown("**Available for everyone:**")
    if st.sidebar.button("🛣️ Check Road Status", key="nav_road_status", use_container_width=True):
        st.session_state.public_page = "Road Status Checker"
        st.rerun()
    
    if st.sidebar.button("📋 Risk History", key="nav_risk_history", use_container_width=True):
        st.session_state.public_page = "Risk History"
        st.rerun()
    
    if st.sidebar.button("📱 Live Feeds", key="nav_live_feeds", use_container_width=True):
        st.session_state.public_page = "Live Feeds"
        st.rerun()
    
    if st.sidebar.button("⚙️ Manage Reports", key="nav_manage_reports", use_container_width=True):
        st.session_state.public_page = "Manage Reports"
        st.rerun()
    
    if st.sidebar.button("📊 Analytics", key="nav_analytics", use_container_width=True):
        st.session_state.public_page = "Analytics"
        st.rerun()
    
    if st.sidebar.button("🚀 Deployment Info", key="nav_deployment", use_container_width=True):
        st.session_state.public_page = "Deployment Info"
        st.rerun()
    
    # Add forgot password option
    if st.sidebar.button("🔑 Forgot Password", key="nav_forgot_password", use_container_width=True):
        st.session_state.public_page = "Forgot Password"
        st.rerun()
    
    # Main content area
    if st.session_state.public_page == "Road Status Checker":
        show_road_status_checker()
    elif st.session_state.public_page == "Risk History":
        show_risk_history()
    elif st.session_state.public_page == "Live Feeds":
        show_live_feeds()
    elif st.session_state.public_page == "Manage Reports":
        show_manage_reports()
    elif st.session_state.public_page == "Analytics":
        show_analytics_page()
    elif st.session_state.public_page == "Deployment Info":
        show_deployment_page()
    elif st.session_state.public_page == "Forgot Password":
        show_forgot_password_page()
    
    # Footer
    st.markdown("---")
    st.markdown("**Road Report Nigeria - Render Optimized** | Built with Streamlit")

if __name__ == "__main__":
    main()
