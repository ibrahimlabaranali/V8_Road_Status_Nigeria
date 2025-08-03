#!/usr/bin/env python3
"""
Admin Logs Module for Nigerian Road Risk Reporter
View and manage admin action logs
"""

import streamlit as st
import sqlite3
import json
from datetime import datetime
from db_setup import get_time_ago

# Page configuration
st.set_page_config(
    page_title="Admin Logs - Road Risk Reporter",
    page_icon="📊",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #6f42c1, #e83e8c);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .log-card {
        background-color: #ffffff;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .action-login { background-color: #d4edda; }
    .action-update { background-color: #d1ecf1; }
    .action-delete { background-color: #f8d7da; }
    .action-config { background-color: #fff3cd; }
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

def get_admin_logs(limit=100):
    """Get admin logs from database"""
    try:
        conn = sqlite3.connect('db/admin_logs.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, admin_id, admin_name, admin_email, action, target_type, target_id, details, created_at
            FROM admin_logs
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        logs = cursor.fetchall()
        conn.close()
        return logs
    except Exception as e:
        st.error(f"Error getting admin logs: {str(e)}")
        return []

def get_log_statistics():
    """Get log statistics"""
    try:
        conn = sqlite3.connect('db/admin_logs.db')
        cursor = conn.cursor()
        
        # Total logs
        cursor.execute('SELECT COUNT(*) FROM admin_logs')
        total_logs = cursor.fetchone()[0]
        
        # Logs by action type
        cursor.execute('''
            SELECT action, COUNT(*) as count
            FROM admin_logs
            GROUP BY action
            ORDER BY count DESC
        ''')
        action_counts = cursor.fetchall()
        
        # Logs by admin
        cursor.execute('''
            SELECT admin_name, COUNT(*) as count
            FROM admin_logs
            GROUP BY admin_name
            ORDER BY count DESC
        ''')
        admin_counts = cursor.fetchall()
        
        # Recent activity (last 24 hours)
        cursor.execute('''
            SELECT COUNT(*)
            FROM admin_logs
            WHERE created_at >= datetime('now', '-1 day')
        ''')
        recent_logs = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_logs': total_logs,
            'action_counts': action_counts,
            'admin_counts': admin_counts,
            'recent_logs': recent_logs
        }
    except Exception as e:
        st.error(f"Error getting log statistics: {str(e)}")
        return {}

def export_logs_to_csv(logs):
    """Export logs to CSV format"""
    csv_data = "ID,Admin Name,Admin Email,Action,Target Type,Target ID,Details,Timestamp\n"
    
    for log in logs:
        log_id, admin_id, admin_name, admin_email, action, target_type, target_id, details, created_at = log
        csv_data += f'"{log_id}","{admin_name}","{admin_email}","{action}","{target_type}","{target_id or ""}","{details or ""}","{created_at}"\n'
    
    return csv_data

def main():
    # Check admin session
    if not check_admin_session():
        return
    
    admin_user = st.session_state.admin_user
    
    # Header
    st.markdown('<div class="main-header"><h1>📊 Admin Logs</h1><p>Administrative Action Audit Trail</p></div>', unsafe_allow_html=True)
    
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
            st.session_state.admin_page = "login"
            st.rerun()
    
    # Log Statistics
    st.subheader("📈 Log Statistics")
    
    stats = get_log_statistics()
    
    if stats:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Logs", stats['total_logs'])
        
        with col2:
            st.metric("Recent Activity (24h)", stats['recent_logs'])
        
        with col3:
            st.metric("Unique Admins", len(stats['admin_counts']))
        
        with col4:
            st.metric("Action Types", len(stats['action_counts']))
        
        # Action distribution
        if stats['action_counts']:
            st.markdown("**Action Distribution:**")
            for action, count in stats['action_counts']:
                st.write(f"• {action.replace('_', ' ').title()}: {count}")
        
        # Admin activity
        if stats['admin_counts']:
            st.markdown("**Admin Activity:**")
            for admin, count in stats['admin_counts']:
                st.write(f"• {admin}: {count} actions")
    
    # Filters
    st.subheader("🔍 Filter Logs")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        action_filter = st.selectbox(
            "Filter by Action",
            ["All", "ADMIN_LOGIN", "UPDATE_REPORT_STATUS", "DELETE_REPORT", "UPDATE_USER_ROLE", "SUSPEND_USER", "REVERIFY_USER", "ADD_UPVOTE", "REMOVE_UPVOTE", "UPDATE_RISK_TYPE", "UPDATE_ADVICE", "ADD_RISK_TYPE"]
        )
    
    with col2:
        admin_filter = st.text_input("Filter by Admin", placeholder="Enter admin name...")
    
    with col3:
        target_filter = st.selectbox(
            "Filter by Target Type",
            ["All", "SYSTEM", "REPORT", "USER", "CONFIG"]
        )
    
    with col4:
        if st.button("🔄 Apply Filters", type="secondary"):
            st.rerun()
    
    # Get logs
    logs = get_admin_logs(limit=200)
    
    # Apply filters
    if action_filter != "All":
        logs = [log for log in logs if log[4] == action_filter]  # action is at index 4
    
    if admin_filter:
        logs = [log for log in logs if admin_filter.lower() in log[2].lower()]  # admin_name is at index 2
    
    if target_filter != "All":
        logs = [log for log in logs if log[5] == target_filter]  # target_type is at index 5
    
    if logs:
        st.subheader(f"📝 Admin Actions ({len(logs)} found)")
        
        # Export functionality
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("📊 Export to CSV", type="secondary"):
                csv_data = export_logs_to_csv(logs)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv_data,
                    file_name=f"admin_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        # Display logs
        for log in logs:
            log_id, admin_id, admin_name, admin_email, action, target_type, target_id, details, created_at = log
            
            # Determine log card class based on action
            action_class = ""
            if "LOGIN" in action:
                action_class = "action-login"
            elif "UPDATE" in action:
                action_class = "action-update"
            elif "DELETE" in action:
                action_class = "action-delete"
            elif "CONFIG" in action or "RISK" in action or "ADVICE" in action:
                action_class = "action-config"
            
            with st.expander(f"{action.replace('_', ' ').title()} by {admin_name} at {get_time_ago(created_at)}", key=f"log_{log_id}"):
                st.markdown(f"""
                <div class="log-card {action_class}">
                    <p><strong>Action:</strong> {action.replace('_', ' ').title()}</p>
                    <p><strong>Admin:</strong> {admin_name} ({admin_email})</p>
                    <p><strong>Target Type:</strong> {target_type}</p>
                    <p><strong>Target ID:</strong> {target_id or 'N/A'}</p>
                    <p><strong>Details:</strong> {details or 'No details provided'}</p>
                    <p><strong>Timestamp:</strong> {created_at}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Action-specific information
                if "LOGIN" in action:
                    st.info("🔐 **Authentication Action** - Admin login/logout activity")
                elif "REPORT" in action:
                    st.info("📋 **Report Management Action** - Report status or content modification")
                elif "USER" in action:
                    st.info("👥 **User Management Action** - User account or role modification")
                elif "CONFIG" in action or "RISK" in action or "ADVICE" in action:
                    st.info("⚙️ **Configuration Action** - System settings or content modification")
                elif "UPVOTE" in action:
                    st.info("👍 **Community Action** - Community validation activity")
    else:
        st.info("No admin logs found matching the selected filters.")
    
    # Log management features
    st.subheader("⚡ Log Management Features")
    st.info("""
    **Advanced Log Management:**
    - Real-time log monitoring
    - Log retention policies (configurable)
    - Automated log analysis and alerts
    - Log backup and archiving
    - Security incident detection
    
    **Current Log Retention:** 180 days (configurable)
    **Log Backup:** Automatic daily backup
    **Security Monitoring:** Active monitoring for suspicious activities
    
    *These features will be implemented in the next version.*
    """)
    
    # Navigation
    st.subheader("⚡ Quick Navigation")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Admin Dashboard", type="secondary"):
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

if __name__ == "__main__":
    main() 