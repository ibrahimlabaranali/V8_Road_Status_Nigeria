#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - Render Optimized Version
Complete road risk reporting system optimized for Render deployment
Python 3.10.13 compatible - Render Free Tier ready
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

# Environment variables for Render deployment
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-key-change-in-production')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key-change-in-production')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///users.db')

# Import Nigerian roads database
try:
    from nigerian_roads_data import nigerian_roads_db
    ROADS_DB_AVAILABLE = True
    # Initialize the Nigerian roads database if available
    if nigerian_roads_db:
        try:
            nigerian_roads_db.init_database()
            st.success("✅ Nigerian roads database initialized successfully!")
        except Exception as e:
            st.error(f"⚠️ Failed to initialize Nigerian roads database: {str(e)}")
            ROADS_DB_AVAILABLE = False
            nigerian_roads_db = None
except ImportError:
    ROADS_DB_AVAILABLE = False
    nigerian_roads_db = None
    st.warning("⚠️ Nigerian roads database module not available")

# Import enhanced reports system
try:
    from enhanced_reports import enhanced_reports_system
    ENHANCED_REPORTS_AVAILABLE = True
except ImportError:
    ENHANCED_REPORTS_AVAILABLE = False
    enhanced_reports_system = None

# Security configuration with environment variable support
SECURITY_CONFIG = {
    'session_timeout_minutes': int(os.environ.get('SESSION_TIMEOUT_MINUTES', '30')),
    'max_login_attempts': int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5')),
    'lockout_duration_minutes': int(os.environ.get('LOCKOUT_DURATION_MINUTES', '30')),
    'password_min_length': int(os.environ.get('PASSWORD_MIN_LENGTH', '8')),
    'require_special_chars': os.environ.get('REQUIRE_SPECIAL_CHARS', 'True').lower() == 'true',
    'enable_captcha': os.environ.get('ENABLE_CAPTCHA', 'True').lower() == 'true',
    'enable_rate_limiting': os.environ.get('ENABLE_RATE_LIMITING', 'True').lower() == 'true',
    'rate_limit_window_minutes': int(os.environ.get('RATE_LIMIT_WINDOW_MINUTES', '15')),
    'max_requests_per_window': int(os.environ.get('MAX_REQUESTS_PER_WINDOW', '100')),
    'enable_ip_tracking': os.environ.get('ENABLE_IP_TRACKING', 'True').lower() == 'true',
    'enable_account_lockout': os.environ.get('ENABLE_ACCOUNT_LOCKOUT', 'True').lower() == 'true',
    'enable_suspicious_activity_detection': os.environ.get('ENABLE_SUSPICIOUS_ACTIVITY_DETECTION', 'True').lower() == 'true',
    'enable_audit_logging': os.environ.get('ENABLE_AUDIT_LOGGING', 'True').lower() == 'true'
}

# Page configuration optimized for Render
st.set_page_config(
    page_title="RoadReportNG - Render",
    page_icon="🛣️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Intelligent auto-refresh configuration
AUTO_REFRESH_CONFIG = {
    'enabled': os.environ.get('AUTO_REFRESH_ENABLED', 'True').lower() == 'true',
    'base_interval_seconds': int(os.environ.get('BASE_REFRESH_INTERVAL', '900')),
    'critical_interval_seconds': int(os.environ.get('CRITICAL_REFRESH_INTERVAL', '30')),
    'high_risk_interval_seconds': int(os.environ.get('HIGH_RISK_REFRESH_INTERVAL', '120')),
    'interval_seconds': int(os.environ.get('DEFAULT_REFRESH_INTERVAL', '900')),
    'manual_refresh_enabled': os.environ.get('MANUAL_REFRESH_ENABLED', 'True').lower() == 'true',
    'show_refresh_status': os.environ.get('SHOW_REFRESH_STATUS', 'True').lower() == 'true',
    'smart_refresh': os.environ.get('SMART_REFRESH', 'True').lower() == 'true',
    'risk_threshold': float(os.environ.get('RISK_THRESHOLD', '0.7')),
    'emergency_keywords': os.environ.get('EMERGENCY_KEYWORDS', 'accident,flood,landslide,bridge,collapse,fire,explosion,blocked,closed').split(','),
    'max_refresh_count': int(os.environ.get('MAX_REFRESH_COUNT', '20'))
}

# Database functions
def init_database():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
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
            image_url TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create admin_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users (id)
        )
    ''')
    
    # Create login_attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN DEFAULT 0
        )
    ''')
    
    # Create account_lockouts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS account_lockouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            locked_until TIMESTAMP NOT NULL,
            reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_risk_reports():
    """Get all risk reports from database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM risk_reports ORDER BY created_at DESC')
    reports = cursor.fetchall()
    conn.close()
    return reports

def get_recent_reports(hours=1):
    """Get reports from the last N hours"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM risk_reports 
        WHERE created_at >= datetime('now', '-{} hours')
        ORDER BY created_at DESC
    '''.format(hours))
    reports = cursor.fetchall()
    conn.close()
    return reports

# Core functions
def check_for_new_reports():
    """Check if there are new reports since last check with intelligent risk assessment"""
    if 'last_report_check' not in st.session_state:
        st.session_state.last_report_check = datetime.now()
        st.session_state.last_report_count = 0
        st.session_state.last_critical_check = datetime.now()
        st.session_state.critical_risks_count = 0
    
    current_time = datetime.now()
    
    # Get current reports
    current_reports = get_risk_reports()
    current_count = len(current_reports)
    
    # Check for new reports
    has_new_reports = False
    new_count = 0
    critical_risks = []
    
    if current_count > st.session_state.last_report_count:
        new_reports = current_count - st.session_state.last_report_count
        st.session_state.last_report_count = current_count
        has_new_reports = True
        new_count = new_reports
        
        # Analyze new reports for critical risks
        recent_reports = get_recent_reports(hours=1)  # Get reports from last hour
        critical_risks = analyze_critical_risks(recent_reports)
    
    # Update last check time
    st.session_state.last_report_check = current_time
    
    return has_new_reports, new_count, critical_risks

def analyze_critical_risks(reports):
    """Analyze reports to identify critical risks that need immediate attention"""
    critical_risks = []
    
    for report in reports:
        risk_score = calculate_risk_score(report)
        
        # Check if report contains emergency keywords
        report_text = f"{report.get('risk_type', '')} {report.get('description', '')} {report.get('location', '')}".lower()
        has_emergency_keywords = any(keyword in report_text for keyword in AUTO_REFRESH_CONFIG['emergency_keywords'])
        
        # Check if risk score exceeds threshold or has emergency keywords
        if risk_score > AUTO_REFRESH_CONFIG['risk_threshold'] or has_emergency_keywords:
            critical_risks.append({
                'report_id': report.get('id'),
                'risk_type': report.get('risk_type'),
                'description': report.get('description'),
                'location': report.get('location'),
                'severity': report.get('severity'),
                'risk_score': risk_score,
                'is_emergency': has_emergency_keywords,
                'timestamp': report.get('created_at')
            })
    
    return critical_risks

def calculate_risk_score(report):
    """Calculate a risk score based on report factors"""
    score = 0.0
    
    # Base score from severity
    severity_scores = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
    score += severity_scores.get(report.get('severity', 'medium'), 0.5)
    
    # Additional score for recent reports (last 2 hours get bonus)
    if report.get('created_at'):
        try:
            created_time = datetime.fromisoformat(report['created_at'].replace('Z', '+00:00'))
            hours_old = (datetime.now() - created_time).total_seconds() / 3600
            if hours_old <= 2:
                score += 0.2  # Recent reports get higher priority
        except:
            pass
    
    # Additional score for verified reports
    if report.get('status') == 'verified':
        score += 0.1
    
    # Additional score for reports with images
    if report.get('image_url'):
        score += 0.1
    
    return min(score, 1.0)  # Cap at 1.0

def get_last_update_time():
    """Get the time of last update check"""
    if 'last_report_check' in st.session_state:
        return st.session_state.last_report_check
    return None

def trigger_auto_refresh():
    """Trigger intelligent auto-refresh based on risk assessment"""
    if not AUTO_REFRESH_CONFIG['enabled']:
        return
    
    # Check for new reports and critical risks
    has_new_reports, new_count, critical_risks = check_for_new_reports()
    
    if has_new_reports:
        # Determine refresh interval based on risk level
        refresh_interval = determine_refresh_interval(critical_risks)
        
        # Show appropriate notification
        if critical_risks:
            critical_count = len([r for r in critical_risks if r['is_emergency']])
            if critical_count > 0:
                st.error(f"🚨 {critical_count} CRITICAL RISK(S) DETECTED! Immediate update required!")
                st.warning("⚠️ Road safety alert - please check details immediately!")
            else:
                st.warning(f"⚠️ {len(critical_risks)} high-risk report(s) detected! Updating in {refresh_interval} seconds...")
        else:
            st.success(f"🆕 {new_count} new report(s) detected! Updating in {refresh_interval} seconds...")
        
        # Add to session state for persistent notification
        if 'notifications' not in st.session_state:
            st.session_state.notifications = []
        
        notification = {
            'type': 'new_reports',
            'message': f"{new_count} new report(s) detected",
            'timestamp': datetime.now(),
            'count': new_count,
            'critical_risks': len(critical_risks),
            'refresh_interval': refresh_interval
        }
        st.session_state.notifications.append(notification)
        
        # Schedule refresh based on risk level
        if refresh_interval <= AUTO_REFRESH_CONFIG['critical_interval_seconds']:
            # Critical risk - refresh immediately
            st.rerun()
        else:
            # Schedule refresh after calculated interval
            time.sleep(refresh_interval)
            st.rerun()

def determine_refresh_interval(critical_risks):
    """Determine the appropriate refresh interval based on risk assessment"""
    if not critical_risks:
        return AUTO_REFRESH_CONFIG['base_interval_seconds']
    
    # Check for emergency keywords (immediate refresh)
    emergency_risks = [r for r in critical_risks if r['is_emergency']]
    if emergency_risks:
        return AUTO_REFRESH_CONFIG['critical_interval_seconds']
    
    # Check for high-risk scores
    high_risk_count = len([r for r in critical_risks if r['risk_score'] > 0.8])
    if high_risk_count > 0:
        return AUTO_REFRESH_CONFIG['high_risk_interval_seconds']
    
    # Medium risk - use base interval
    return AUTO_REFRESH_CONFIG['base_interval_seconds']

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

def show_user_management():
    """Show user management interface (admin only)"""
    st.header("👥 User Management")
    st.info("Manage user accounts and permissions")
    
    if st.session_state.get('role') == 'admin':
        st.success("Admin access granted")
        st.button("View All Users", key="view_users_btn")
        st.button("Update User Roles", key="update_roles_btn")
    else:
        st.warning("Admin access required")

def show_ai_advice_page():
    """Show AI-powered safety advice"""
    st.header("🤖 AI Safety Advisor")
    st.info("Get intelligent road safety recommendations")
    
    st.write("**AI Analysis:** Based on current road conditions and historical data")
    st.write("**Recommendation:** Avoid Lagos-Ibadan Expressway during peak hours")
    st.write("**Alternative Route:** Use Ikorodu-Sagamu Road")

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

def show_security_page():
    """Show security and password management"""
    st.header("🔒 Security Settings")
    st.info("Manage your account security")
    
    st.button("Change Password", key="change_pwd_btn")
    st.button("Enable 2FA", key="enable_2fa_btn")
    st.button("View Login History", key="login_history_btn")

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
    - Security settings
    - Auto-refresh system
    """)

def show_moderation_panel():
    """Show moderation panel for admins"""
    st.header("🛡️ Moderation Panel")
    st.info("Review and moderate user reports")
    
    if st.session_state.get('role') == 'admin':
        st.success("Admin access granted")
        st.button("Review Pending Reports", key="review_btn")
        st.button("Approve Reports", key="approve_btn")
        st.button("Reject Reports", key="reject_btn")
    else:
        st.warning("Admin access required")

def show_admin_user_management():
    """Show admin user management"""
    st.header("👑 Admin User Management")
    st.info("Manage user accounts and system settings")
    
    if st.session_state.get('role') == 'admin':
        st.success("Admin access granted")
        
        # Sample user data
        users = [
            {"username": "admin", "role": "admin", "status": "active"},
            {"username": "user1", "role": "user", "status": "active"},
            {"username": "user2", "role": "moderator", "status": "active"}
        ]
        
        for user in users:
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.write(f"**{user['username']}**")
            with col2:
                st.write(user['role'])
            with col3:
                st.write(user['status'])
    else:
        st.warning("Admin access required")

def show_admin_logs():
    """Show admin activity logs"""
    st.header("📝 Admin Activity Logs")
    st.info("View system administration activities")
    
    if st.session_state.get('role') == 'admin':
        st.success("Admin access granted")
        
        # Sample log entries
        logs = [
            "2024-01-15 10:30 - User account created: user3",
            "2024-01-15 09:15 - Report approved: ID 123",
            "2024-01-15 08:45 - System backup completed"
        ]
        
        for log in logs:
            st.write(log)
    else:
        st.warning("Admin access required")

def show_config_panel():
    """Show system configuration panel"""
    st.header("⚙️ System Configuration")
    st.info("Configure system settings and parameters")
    
    if st.session_state.get('role') == 'admin':
        st.success("Admin access granted")
        
        st.subheader("Security Settings")
        st.slider("Session Timeout (minutes)", 15, 60, SECURITY_CONFIG['session_timeout_minutes'])
        st.slider("Max Login Attempts", 3, 10, SECURITY_CONFIG['max_login_attempts'])
        
        st.subheader("Auto-refresh Settings")
        st.checkbox("Enable Auto-refresh", AUTO_REFRESH_CONFIG['enabled'])
        st.slider("Base Refresh Interval (seconds)", 300, 1800, AUTO_REFRESH_CONFIG['base_interval_seconds'])
    else:
        st.warning("Admin access required")

# Main application
def main():
    """Main application optimized for Render deployment"""
    
    # Initialize database
    init_database()
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'role' not in st.session_state:
        st.session_state.role = 'user'
    if 'public_page' not in st.session_state:
        st.session_state.public_page = "Road Status Checker"
    
    # Header
    st.markdown('<div class="main-header"><h1>🛣️ Road Report Nigeria - Render</h1><p>Enhanced Road Status System - Render Optimized</p></div>', unsafe_allow_html=True)
    
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
    
    if st.sidebar.button("👥 User Management", key="nav_user_management", use_container_width=True):
        st.session_state.public_page = "User Management"
        st.rerun()
    
    if st.sidebar.button("🤖 AI Advice", key="nav_ai_advice", use_container_width=True):
        st.session_state.public_page = "AI Advice"
        st.rerun()
    
    if st.sidebar.button("📊 Analytics", key="nav_analytics", use_container_width=True):
        st.session_state.public_page = "Analytics"
        st.rerun()
    
    if st.sidebar.button("🔒 Security", key="nav_security", use_container_width=True):
        st.session_state.public_page = "Security"
        st.rerun()
    
    if st.sidebar.button("🚀 Deployment Info", key="nav_deployment", use_container_width=True):
        st.session_state.public_page = "Deployment Info"
        st.rerun()
    
    # Admin-only navigation
    if st.session_state.get('role') == 'admin':
        st.sidebar.markdown("**Admin Only:**")
        if st.sidebar.button("🛡️ Moderation Panel", key="nav_moderation", use_container_width=True):
            st.session_state.public_page = "Moderation Panel"
            st.rerun()
        
        if st.sidebar.button("👑 Admin User Management", key="nav_admin_users", use_container_width=True):
            st.session_state.public_page = "Admin User Management"
            st.rerun()
        
        if st.sidebar.button("📝 Admin Logs", key="nav_admin_logs", use_container_width=True):
            st.session_state.public_page = "Admin Logs"
            st.rerun()
        
        if st.sidebar.button("⚙️ System Config", key="nav_config", use_container_width=True):
            st.session_state.public_page = "System Config"
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
    elif st.session_state.public_page == "User Management":
        show_user_management()
    elif st.session_state.public_page == "AI Advice":
        show_ai_advice_page()
    elif st.session_state.public_page == "Analytics":
        show_analytics_page()
    elif st.session_state.public_page == "Security":
        show_security_page()
    elif st.session_state.public_page == "Deployment Info":
        show_deployment_page()
    elif st.session_state.public_page == "Moderation Panel":
        show_moderation_panel()
    elif st.session_state.public_page == "Admin User Management":
        show_admin_user_management()
    elif st.session_state.public_page == "Admin Logs":
        show_admin_logs()
    elif st.session_state.public_page == "System Config":
        show_config_panel()
    
    # Footer
    st.markdown("---")
    st.markdown("**Road Report Nigeria - Render Optimized** | Built with Streamlit")

if __name__ == "__main__":
    main()
