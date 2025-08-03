#!/usr/bin/env python3
"""
Community Validation Module for Nigerian Road Risk Reporter
Upvote system and community-driven report validation
"""

import streamlit as st
import sqlite3
import json
from datetime import datetime
from db_setup import log_admin_action, get_time_ago

# Page configuration
st.set_page_config(
    page_title="Community Validation - Road Risk Reporter",
    page_icon="👍",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #ffc107, #fd7e14);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .report-card {
        background-color: #ffffff;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .upvote-section {
        background-color: #f8f9fa;
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
        st.switch_page("admin_login.py")
        return False
    return True

def get_reports_with_upvotes():
    """Get reports with upvote information"""
    try:
        conn = sqlite3.connect('db/risk_reports.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, u.full_name as reporter_name
            FROM risk_reports r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.upvotes DESC, r.created_at DESC
        ''')
        
        reports = cursor.fetchall()
        conn.close()
        return reports
    except Exception as e:
        st.error(f"Error getting reports: {str(e)}")
        return []

def get_upvote_count(report_id: int):
    """Get upvote count for a specific report"""
    try:
        conn = sqlite3.connect('db/upvotes.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM upvotes WHERE report_id = ?', (report_id,))
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
    except Exception as e:
        st.error(f"Error getting upvote count: {str(e)}")
        return 0

def has_user_upvoted(report_id: int, user_id: int):
    """Check if user has already upvoted a report"""
    try:
        conn = sqlite3.connect('db/upvotes.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM upvotes WHERE report_id = ? AND user_id = ?', (report_id, user_id))
        result = cursor.fetchone()
        
        conn.close()
        return result is not None
    except Exception as e:
        st.error(f"Error checking upvote: {str(e)}")
        return False

def add_upvote(report_id: int, user_id: int, admin_user: dict):
    """Add upvote to a report"""
    try:
        conn = sqlite3.connect('db/upvotes.db')
        cursor = conn.cursor()
        
        # Check if user already upvoted
        cursor.execute('SELECT id FROM upvotes WHERE report_id = ? AND user_id = ?', (report_id, user_id))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return False, "You have already upvoted this report"
        
        # Add upvote
        cursor.execute('INSERT INTO upvotes (report_id, user_id) VALUES (?, ?)', (report_id, user_id))
        
        # Update report upvote count
        conn2 = sqlite3.connect('db/risk_reports.db')
        cursor2 = conn2.cursor()
        cursor2.execute('UPDATE risk_reports SET upvotes = upvotes + 1 WHERE id = ?', (report_id,))
        
        conn.commit()
        conn2.commit()
        conn.close()
        conn2.close()
        
        # Log admin action
        log_admin_action(
            admin_id=admin_user['id'],
            admin_name=admin_user['full_name'],
            admin_email=admin_user['email'],
            action="ADD_UPVOTE",
            target_type="REPORT",
            target_id=report_id,
            details=f"Added upvote to report #{report_id}"
        )
        
        return True, "Report upvoted successfully"
    except Exception as e:
        return False, f"Failed to upvote: {str(e)}"

def remove_upvote(report_id: int, user_id: int, admin_user: dict):
    """Remove upvote from a report"""
    try:
        conn = sqlite3.connect('db/upvotes.db')
        cursor = conn.cursor()
        
        # Remove upvote
        cursor.execute('DELETE FROM upvotes WHERE report_id = ? AND user_id = ?', (report_id, user_id))
        
        if cursor.rowcount > 0:
            # Update report upvote count
            conn2 = sqlite3.connect('db/risk_reports.db')
            cursor2 = conn2.cursor()
            cursor2.execute('UPDATE risk_reports SET upvotes = upvotes - 1 WHERE id = ?', (report_id,))
            
            conn.commit()
            conn2.commit()
            conn.close()
            conn2.close()
            
            # Log admin action
            log_admin_action(
                admin_id=admin_user['id'],
                admin_name=admin_user['full_name'],
                admin_email=admin_user['email'],
                action="REMOVE_UPVOTE",
                target_type="REPORT",
                target_id=report_id,
                details=f"Removed upvote from report #{report_id}"
            )
            
            return True, "Upvote removed successfully"
        else:
            conn.close()
            return False, "No upvote found to remove"
    except Exception as e:
        return False, f"Failed to remove upvote: {str(e)}"

def get_community_stats():
    """Get community validation statistics"""
    try:
        conn = sqlite3.connect('db/upvotes.db')
        cursor = conn.cursor()
        
        # Total upvotes
        cursor.execute('SELECT COUNT(*) FROM upvotes')
        total_upvotes = cursor.fetchone()[0]
        
        # Unique users who have upvoted
        cursor.execute('SELECT COUNT(DISTINCT user_id) FROM upvotes')
        unique_voters = cursor.fetchone()[0]
        
        # Most upvoted reports
        cursor.execute('''
            SELECT report_id, COUNT(*) as upvote_count
            FROM upvotes
            GROUP BY report_id
            ORDER BY upvote_count DESC
            LIMIT 5
        ''')
        top_reports = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_upvotes': total_upvotes,
            'unique_voters': unique_voters,
            'top_reports': top_reports
        }
    except Exception as e:
        st.error(f"Error getting community stats: {str(e)}")
        return {}

def main():
    # Check admin session
    if not check_admin_session():
        return
    
    admin_user = st.session_state.admin_user
    
    # Header
    st.markdown('<div class="main-header"><h1>👍 Community Validation</h1><p>Community-driven Report Validation System</p></div>', unsafe_allow_html=True)
    
    # Admin info and navigation
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.success(f"🔐 Admin: {admin_user['full_name']}")
        st.info(f"Email: {admin_user['email']}")
    
    with col2:
        if st.button("🔄 Refresh", type="secondary"):
            st.rerun()
    
    with col3:
        if st.button("🚪 Logout", type="secondary"):
            st.session_state.admin_logged_in = False
            st.session_state.admin_user = None
            st.switch_page("admin_login.py")
    
    # Community Statistics
    st.subheader("📊 Community Statistics")
    
    stats = get_community_stats()
    
    if stats:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Upvotes", stats['total_upvotes'])
        
        with col2:
            st.metric("Unique Voters", stats['unique_voters'])
        
        with col3:
            avg_upvotes = stats['total_upvotes'] / max(stats['unique_voters'], 1)
            st.metric("Avg Upvotes per Voter", f"{avg_upvotes:.1f}")
    
    # Filters
    st.subheader("🔍 Filter Reports")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "pending", "verified", "resolved", "false"]
        )
    
    with col2:
        min_upvotes = st.number_input("Minimum Upvotes", min_value=0, value=0)
    
    with col3:
        if st.button("🔄 Apply Filters", type="secondary"):
            st.rerun()
    
    # Get reports
    reports = get_reports_with_upvotes()
    
    # Apply filters
    if status_filter != "All":
        reports = [r for r in reports if r[7] == status_filter]  # status is at index 7
    
    reports = [r for r in reports if r[9] >= min_upvotes]  # upvotes is at index 9
    
    if reports:
        st.subheader(f"📋 Reports for Community Validation ({len(reports)} found)")
        
        for report in reports:
            report_id, user_id, risk_type, description, location, lat, lon, status, confirmations, upvotes, created_at, reporter_name = report
            
            with st.expander(f"Report #{report_id} - {risk_type} at {location} (👍 {upvotes} upvotes)"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"""
                    **Risk Type:** {risk_type}  
                    **Location:** 📍 {location}  
                    **Description:** {description}  
                    **Reporter:** {reporter_name}  
                    **Created:** {created_at}  
                    **Status:** {status.title()}  
                    **Confirmations:** ✅ {confirmations}
                    """)
                
                with col2:
                    st.markdown("**Community Validation:**")
                    
                    # Show upvote count
                    st.markdown(f"👍 **{upvotes} upvotes**")
                    
                    # Check if admin has upvoted
                    admin_has_upvoted = has_user_upvoted(report_id, admin_user['id'])
                    
                    if admin_has_upvoted:
                        st.success("✅ You upvoted this report")
                        if st.button(f"👎 Remove Upvote #{report_id}", key=f"remove_{report_id}"):
                            success, message = remove_upvote(report_id, admin_user['id'], admin_user)
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)
                    else:
                        if st.button(f"👍 Upvote Report #{report_id}", key=f"upvote_{report_id}"):
                            success, message = add_upvote(report_id, admin_user['id'], admin_user)
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)
                    
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
    
    # Top upvoted reports
    if stats and stats['top_reports']:
        st.subheader("🏆 Top Upvoted Reports")
        
        for report_id, upvote_count in stats['top_reports']:
            # Get report details
            try:
                conn = sqlite3.connect('db/risk_reports.db')
                cursor = conn.cursor()
                cursor.execute('SELECT risk_type, location FROM risk_reports WHERE id = ?', (report_id,))
                report = cursor.fetchone()
                conn.close()
                
                if report:
                    risk_type, location = report
                    st.info(f"Report #{report_id}: {risk_type} at {location} - 👍 {upvote_count} upvotes")
            except:
                st.info(f"Report #{report_id} - 👍 {upvote_count} upvotes")
    
    # GPS validation simulation
    st.subheader("📍 GPS Validation Simulation")
    st.info("""
    **Community GPS Validation (Simulated):**
    
    The system simulates GPS-based validation by:
    - Tracking user upvotes per report
    - Preventing duplicate votes from same user
    - Calculating trust scores based on upvote patterns
    - Simulating location-based validation
    
    **Trust Score Calculation:**
    - Reports with 5+ upvotes: High Trust
    - Reports with 3-4 upvotes: Medium Trust  
    - Reports with 1-2 upvotes: Low Trust
    - Reports with 0 upvotes: Pending Validation
    
    *In production, this would use real GPS coordinates and distance calculations.*
    """)
    
    # Navigation
    st.subheader("⚡ Quick Navigation")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Admin Dashboard", type="secondary"):
            st.switch_page("admin_dashboard.py")
    
    with col2:
        if st.button("⚙️ Config Panel", type="secondary"):
            st.switch_page("admin_config_panel.py")
    
    with col3:
        if st.button("📊 View Logs", type="secondary"):
            st.switch_page("admin_logs.py")

if __name__ == "__main__":
    main() 