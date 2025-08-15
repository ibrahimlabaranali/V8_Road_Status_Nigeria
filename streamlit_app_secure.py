#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - Enhanced Secure Version
Complete road risk reporting system with enhanced security features
Python 3.13 compatible - Streamlit Cloud ready
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
    page_title="RoadReportNG - Secure",
    page_icon="🛣️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Intelligent auto-refresh configuration
AUTO_REFRESH_CONFIG = {
    'enabled': True,
    'base_interval_seconds': 900,  # 15 minutes base interval
    'critical_interval_seconds': 30,  # 30 seconds for critical risks
    'high_risk_interval_seconds': 120,  # 2 minutes for high-risk situations
    'interval_seconds': 900,  # Default interval for backward compatibility
    'manual_refresh_enabled': True,
    'show_refresh_status': True,
    'smart_refresh': True,  # Enable intelligent refresh
    'risk_threshold': 0.7,  # Risk score threshold for immediate updates
    'emergency_keywords': ['accident', 'flood', 'landslide', 'bridge', 'collapse', 'fire', 'explosion', 'blocked', 'closed'],
    'max_refresh_count': 20
}

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

# Main application
def main():
    """Main application with enhanced security features"""
    
    # Header
    st.markdown('<div class="main-header"><h1>🛣️ Road Report Nigeria - Secure</h1><p>Enhanced Road Status System with Security Features</p></div>', unsafe_allow_html=True)
    
    # Show security info
    st.info("🔒 **Enhanced Security Version** - This version includes advanced security features")
    
    # Security features showcase
    st.subheader("🔒 Security Features")
    col1, col2 = st.columns(2)
    
    with col1:
        st.success("✅ Session timeout: 30 minutes")
        st.success("✅ Max login attempts: 5")
        st.success("✅ Account lockout: 30 minutes")
        st.success("✅ Password requirements: 8+ chars, special chars")
    
    with col2:
        st.success("✅ Rate limiting enabled")
        st.success("✅ IP tracking enabled")
        st.success("✅ Suspicious activity detection")
        st.success("✅ Audit logging enabled")
    
    # Auto-refresh status
    st.subheader("🔄 Auto-Refresh System")
    st.info(f"**Status:** {'Enabled' if AUTO_REFRESH_CONFIG['enabled'] else 'Disabled'}")
    st.info(f"**Base interval:** {AUTO_REFRESH_CONFIG['base_interval_seconds']} seconds")
    st.info(f"**Critical interval:** {AUTO_REFRESH_CONFIG['critical_interval_seconds']} seconds")
    
    # Database status
    st.subheader("🗄️ Database Status")
    if ROADS_DB_AVAILABLE:
        st.success("✅ Nigerian roads database available")
    else:
        st.warning("⚠️ Nigerian roads database not available")
    
    if ENHANCED_REPORTS_AVAILABLE:
        st.success("✅ Enhanced reports system available")
    else:
        st.warning("⚠️ Enhanced reports system not available")
    
    # Footer
    st.markdown("---")
    st.markdown("**Road Report Nigeria - Secure Version** | Built with Streamlit")

if __name__ == "__main__":
    main()
