#!/usr/bin/env python3
"""
Admin Dashboard Module for Nigerian Road Risk Reporter
Report statistics, moderation panel, and admin controls
"""

import streamlit as st
import sqlite3
import json
from datetime import datetime, timedelta
from db_setup import log_admin_action, get_time_ago

# Page configuration
st.set_page_config(
    page_title="Admin Dashboard - Road Risk Reporter",
    page_icon="📊",
    layout="wide"
)

# Custom CSS
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
    .metric-card {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }
    .report-card {
        background-color: #ffffff;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .status-pending { background-color: #ffc107; color: black; }
    .status-verified { background-color: #28a745; color: white; }
    .status-resolved { background-color: #007bff; color: white; }
    .status-false { background-color: #dc3545; color: white; }
</style>
""", unsafe_allow_html=True)

def check_admin_session():
    """Check if admin is logged in"""
    if not st.session_state.get("admin_logged_in"):
        st.error("🔐 Access denied. Please login as admin.")
        st.info("Redirecting to admin login...")
        st.session_state.admin_page = "login"
        st.rerun()
        return False
    return True

def get_report_stats():
    """Get report statistics from database"""
    try:
        conn = sqlite3.connect('db/risk_reports.db')
        cursor = conn.cursor()
        
        # Total reports
        cursor.execute('SELECT COUNT(*) FROM risk_reports')
        total_reports = cursor.fetchone()[0]
        
        # Pending reports
        cursor.execute('SELECT COUNT(*) FROM risk_reports WHERE status = "pending"')
        pending_reports = cursor.fetchone()[0]
        
        # Verified reports
        cursor.execute('SELECT COUNT(*) FROM risk_reports WHERE status = "verified"')
        verified_reports = cursor.fetchone()[0]
        
        # Flagged as fake
        cursor.execute('SELECT COUNT(*) FROM risk_reports WHERE status = "false"')
        false_reports = cursor.fetchone()[0]
        
        # Resolved reports
        cursor.execute('SELECT COUNT(*) FROM risk_reports WHERE status = "resolved"')
        resolved_reports = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_reports': total_reports,
            'pending_reports': pending_reports,
            'verified_reports': verified_reports,
            'false_reports': false_reports,
            'resolved_reports': resolved_reports
        }
    except Exception as e:
        st.error(f"Error getting report stats: {str(e)}")
        return {}

def get_recent_reports(limit=10):
    """Get recent reports for moderation"""
    try:
        conn = sqlite3.connect('db/risk_reports.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, u.full_name as reporter_name
            FROM risk_reports r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
            LIMIT ?
        ''', (limit,))
        
        reports = cursor.fetchall()
        conn.close()
        return reports
    except Exception as e:
        st.error(f"Error getting recent reports: {str(e)}")
        return []

def update_report_status(report_id: int, status: str, admin_user: dict):
    """Update report status and log action"""
    try:
        conn = sqlite3.connect('db/risk_reports.db')
        cursor = conn.cursor()
        
        # Get report details for logging
        cursor.execute('SELECT risk_type, location FROM risk_reports WHERE id = ?', (report_id,))
        report = cursor.fetchone()
        
        if report:
            risk_type, location = report
            
            # Update status
            cursor.execute('UPDATE risk_reports SET status = ? WHERE id = ?', (status, report_id))
            conn.commit()
            
            # Log admin action
            log_admin_action(
                admin_id=admin_user['id'],
                admin_name=admin_user['full_name'],
                admin_email=admin_user['email'],
                action=f"UPDATE_REPORT_STATUS",
                target_type="REPORT",
                target_id=report_id,
                details=f"Changed status to {status} for {risk_type} report at {location}"
            )
            
            conn.close()
            return True
        else:
            conn.close()
            return False
    except Exception as e:
        st.error(f"Error updating report status: {str(e)}")
        return False

def delete_report(report_id: int, admin_user: dict):
    """Delete report and log action"""
    try:
        conn = sqlite3.connect('db/risk_reports.db')
        cursor = conn.cursor()
        
        # Get report details for logging
        cursor.execute('SELECT risk_type, location FROM risk_reports WHERE id = ?', (report_id,))
        report = cursor.fetchone()
        
        if report:
            risk_type, location = report
            
            # Delete report
            cursor.execute('DELETE FROM risk_reports WHERE id = ?', (report_id,))
            conn.commit()
            
            # Log admin action
            log_admin_action(
                admin_id=admin_user['id'],
                admin_name=admin_user['full_name'],
                admin_email=admin_user['email'],
                action="DELETE_REPORT",
                target_type="REPORT",
                target_id=report_id,
                details=f"Deleted {risk_type} report at {location}"
            )
            
            conn.close()
            return True
        else:
            conn.close()
            return False
    except Exception as e:
        st.error(f"Error deleting report: {str(e)}")
        return False

def main():
    # Check admin session
    if not check_admin_session():
        return
    
    admin_user = st.session_state.admin_user
    
    # Header
    st.markdown('<div class="main-header"><h1>📊 Admin Dashboard</h1><p>Nigerian Road Risk Reporter - Administrative Control Panel</p></div>', unsafe_allow_html=True)
    
    # Admin info and logout
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.success(f"🔐 Welcome, {admin_user['full_name']}!")
        st.info(f"Admin ID: {admin_user['id']} | Email: {admin_user['email']}")
    
    with col2:
        if st.button("🔄 Refresh Data", type="secondary"):
            st.rerun()
    
    with col3:
        if st.button("🚪 Logout", type="secondary"):
            st.session_state.admin_logged_in = False
            st.session_state.admin_user = None
            st.session_state.admin_page = "login"
            st.rerun()
    
    # Report Statistics
    st.subheader("📈 Report Statistics")
    
    stats = get_report_stats()
    
    if stats:
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Reports", stats['total_reports'])
        
        with col2:
            st.metric("Pending", stats['pending_reports'])
        
        with col3:
            st.metric("Verified", stats['verified_reports'])
        
        with col4:
            st.metric("Flagged as Fake", stats['false_reports'])
        
        with col5:
            st.metric("Resolved", stats['resolved_reports'])
    
    # Moderation Panel
    st.subheader("📋 Moderation Panel")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "pending", "verified", "resolved", "false"]
        )
    
    with col2:
        risk_type_filter = st.selectbox(
            "Filter by Risk Type",
            ["All", "Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        )
    
    with col3:
        if st.button("🔄 Refresh Reports", type="secondary"):
            st.rerun()
    
    # Get reports
    reports = get_recent_reports(limit=50)
    
    # Apply filters
    if status_filter != "All":
        reports = [r for r in reports if r[7] == status_filter]  # status is at index 7
    
    if risk_type_filter != "All":
        reports = [r for r in reports if r[2] == risk_type_filter]  # risk_type is at index 2
    
    if reports:
        st.subheader(f"📊 Reports for Moderation ({len(reports)} found)")
        
        for report in reports:
            report_id, user_id, risk_type, description, location, lat, lon, status, confirmations, upvotes, created_at, reporter_name = report
            
            with st.expander(f"Report #{report_id} - {risk_type} at {location} ({status})"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"""
                    **Risk Type:** {risk_type}  
                    **Location:** 📍 {location}  
                    **Description:** {description}  
                    **Reporter:** {reporter_name}  
                    **Created:** {created_at}  
                    **Confirmations:** ✅ {confirmations} | **Upvotes:** 👍 {upvotes}
                    """)
                
                with col2:
                    st.markdown("**Moderation Actions:**")
                    
                    # Action buttons
                    if status == "pending":
                        if st.button(f"✅ Verify #{report_id}", key=f"verify_{report_id}"):
                            if update_report_status(report_id, "verified", admin_user):
                                st.success(f"Report #{report_id} verified!")
                                st.rerun()
                            else:
                                st.error("Failed to verify report")
                    
                    if st.button(f"🚩 Flag as Fake #{report_id}", key=f"flag_{report_id}"):
                        if update_report_status(report_id, "false", admin_user):
                            st.success(f"Report #{report_id} flagged as fake!")
                            st.rerun()
                        else:
                            st.error("Failed to flag report")
                    
                    if st.button(f"🗑️ Delete #{report_id}", key=f"delete_{report_id}"):
                        if delete_report(report_id, admin_user):
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
    
    # Radius-based notifications (mock)
    st.subheader("🚨 Proximity Alerts (20km Radius)")
    st.info("""
    **Simulated Proximity Notifications:**
    
    📍 **Lagos Area**: 3 new reports in your vicinity
    - Report #45: Robbery at Victoria Island (2km away)
    - Report #46: Traffic at Lekki Expressway (5km away)
    - Report #47: Flooding at Ikeja (8km away)
    
    📍 **Abuja Area**: 1 pending report requires attention
    - Report #48: Road Damage at Wuse Zone 2 (3km away)
    
    📍 **Port Harcourt**: 2 verified reports in your area
    - Report #49: Protest at Rumuokoro (4km away)
    - Report #50: Traffic at Aba Road (6km away)
    
    *This is a simulation. In production, this would use real GPS coordinates and distance calculations.*
    """)
    
    # Quick actions
    st.subheader("⚡ Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("👥 User Management", type="secondary"):
            st.session_state.admin_page = "config"
            st.rerun()
    
    with col2:
        if st.button("📊 View Logs", type="secondary"):
            st.session_state.admin_page = "logs"
            st.rerun()
    
    with col3:
        if st.button("👍 Community Validation", type="secondary"):
            st.session_state.admin_page = "community"
            st.rerun()

if __name__ == "__main__":
    main() 