#!/usr/bin/env python3
"""
Admin Configuration Panel Module for Nigerian Road Risk Reporter
User management and risk/advice configuration
"""

import streamlit as st
import sqlite3
import json
import os
from db_setup import log_admin_action, get_time_ago

# Page configuration
st.set_page_config(
    page_title="Admin Config Panel - Road Risk Reporter",
    page_icon="⚙️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #28a745, #17a2b8);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .user-card {
        background-color: #ffffff;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .config-card {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
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

def load_config():
    """Load configuration from config.json"""
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                return json.load(f)
        else:
            # Default configuration
            return {
                "risk_types": [
                    {"name": "Robbery", "color": "#dc3545", "icon": "🚨"},
                    {"name": "Flooding", "color": "#007bff", "icon": "🌊"},
                    {"name": "Protest", "color": "#6f42c1", "icon": "🏛️"},
                    {"name": "Road Damage", "color": "#fd7e14", "icon": "🛣️"},
                    {"name": "Traffic", "color": "#ffc107", "icon": "🚗"},
                    {"name": "Other", "color": "#6c757d", "icon": "📝"}
                ],
                "advice_templates": {
                    "Robbery": "🚨 **Robbery Alert**: Avoid this area, especially at night.",
                    "Flooding": "🌊 **Flooding Warning**: Road may be impassable.",
                    "Protest": "🏛️ **Protest Notice**: Expect traffic delays.",
                    "Road Damage": "🛣️ **Road Damage**: Drive carefully.",
                    "Traffic": "🚗 **Traffic Alert**: Heavy traffic congestion.",
                    "Other": "⚠️ **Road Incident**: Exercise caution."
                },
                "system_settings": {
                    "auto_verify_threshold": 3,
                    "report_retention_days": 90,
                    "log_retention_days": 180,
                    "require_2fa": True,
                    "email_notifications": True,
                    "sms_notifications": False,
                    "push_notifications": True
                }
            }
    except Exception as e:
        st.error(f"Error loading config: {str(e)}")
        return {}

def save_config(config):
    """Save configuration to config.json"""
    try:
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        st.error(f"Error saving config: {str(e)}")
        return False

def get_all_users():
    """Get all users from database"""
    try:
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, full_name, phone_number, email, role, nin_or_passport, created_at
            FROM users
            ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        return users
    except Exception as e:
        st.error(f"Error getting users: {str(e)}")
        return []

def update_user_role(user_id: int, new_role: str, admin_user: dict):
    """Update user role and log action"""
    try:
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        
        # Get user details for logging
        cursor.execute('SELECT full_name FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if user:
            # Update user role
            cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
            conn.commit()
            
            # Log admin action
            log_admin_action(
                admin_id=admin_user['id'],
                admin_name=admin_user['full_name'],
                admin_email=admin_user['email'],
                action="UPDATE_USER_ROLE",
                target_type="USER",
                target_id=user_id,
                details=f"Changed role to {new_role} for user {user[0]}"
            )
            
            conn.close()
            return True
        else:
            conn.close()
            return False
    except Exception as e:
        st.error(f"Error updating user role: {str(e)}")
        return False

def main():
    # Check admin session
    if not check_admin_session():
        return
    
    admin_user = st.session_state.admin_user
    
    # Header
    st.markdown('<div class="main-header"><h1>⚙️ Admin Configuration Panel</h1><p>User Management & System Configuration</p></div>', unsafe_allow_html=True)
    
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
    
    # Tab navigation
    tab1, tab2, tab3 = st.tabs(["👥 User Management", "🚨 Risk Types", "💡 Advice Templates"])
    
    with tab1:
        st.subheader("👥 User Management")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            role_filter = st.selectbox(
                "Filter by Role",
                ["All", "Public", "Driver", "Admin"]
            )
        
        with col2:
            search_term = st.text_input("Search by name or email", placeholder="Enter search term...")
        
        with col3:
            if st.button("🔄 Refresh Users", type="secondary"):
                st.rerun()
        
        # Get users
        users = get_all_users()
        
        # Apply filters
        if role_filter != "All":
            users = [u for u in users if u[4] == role_filter]  # role is at index 4
        
        if search_term:
            users = [u for u in users if search_term.lower() in u[1].lower() or 
                    (u[3] and search_term.lower() in u[3].lower())]  # name at index 1, email at index 3
        
        if users:
            # User statistics
            role_counts = {}
            for user in users:
                role = user[4]
                role_counts[role] = role_counts.get(role, 0) + 1
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Users", len(users))
            with col2:
                st.metric("Public Users", role_counts.get("Public", 0))
            with col3:
                st.metric("Drivers", role_counts.get("Driver", 0))
            with col4:
                st.metric("Admins", role_counts.get("Admin", 0))
            
            # Display users
            st.subheader(f"📊 Users ({len(users)} found)")
            
            for user in users:
                user_id, full_name, phone, email, role, nin, created_at = user
                
                with st.expander(f"User #{user_id} - {full_name} ({role})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"""
                        **Name:** {full_name}  
                        **Phone:** {phone}  
                        **Email:** {email or 'N/A'}  
                        **Role:** {role}  
                        **NIN/Passport:** {nin}  
                        **Registered:** {created_at}
                        """)
                    
                    with col2:
                        st.markdown("**Actions:**")
                        
                        # Role change options
                        if role != "Admin":
                            if st.button(f"👑 Promote to Admin #{user_id}", key=f"promote_{user_id}"):
                                if update_user_role(user_id, "Admin", admin_user):
                                    st.success(f"User #{user_id} promoted to Admin!")
                                    st.rerun()
                                else:
                                    st.error("Failed to promote user")
                        
                        if role != "Driver":
                            if st.button(f"🚗 Make Driver #{user_id}", key=f"driver_{user_id}"):
                                if update_user_role(user_id, "Driver", admin_user):
                                    st.success(f"User #{user_id} role changed to Driver!")
                                    st.rerun()
                                else:
                                    st.error("Failed to change user role")
                        
                        if role != "Public":
                            if st.button(f"👤 Make Public #{user_id}", key=f"public_{user_id}"):
                                if update_user_role(user_id, "Public", admin_user):
                                    st.success(f"User #{user_id} role changed to Public!")
                                    st.rerun()
                                else:
                                    st.error("Failed to change user role")
                        
                        # Suspend user (simulated)
                        if st.button(f"⏸️ Suspend #{user_id}", key=f"suspend_{user_id}"):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                admin_email=admin_user['email'],
                                action="SUSPEND_USER",
                                target_type="USER",
                                target_id=user_id,
                                details=f"Suspended user {full_name} (ID: {user_id})"
                            )
                            st.success(f"User #{user_id} suspended!")
                            st.rerun()
                        
                        # Re-verify user (simulated)
                        if st.button(f"✅ Re-verify #{user_id}", key=f"reverify_{user_id}"):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                admin_email=admin_user['email'],
                                action="REVERIFY_USER",
                                target_type="USER",
                                target_id=user_id,
                                details=f"Re-verified user {full_name} (ID: {user_id})"
                            )
                            st.success(f"User #{user_id} re-verified!")
                            st.rerun()
        else:
            st.info("No users found matching the selected filters.")
    
    with tab2:
        st.subheader("🚨 Risk Types Configuration")
        
        config = load_config()
        
        if config and 'risk_types' in config:
            st.markdown("**Current Risk Types:**")
            
            for i, risk_type in enumerate(config['risk_types']):
                with st.expander(f"{risk_type['icon']} {risk_type['name']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        new_name = st.text_input(f"Name", value=risk_type['name'], key=f"risk_name_{i}")
                        new_color = st.color_picker(f"Color", value=risk_type['color'], key=f"risk_color_{i}")
                    
                    with col2:
                        new_icon = st.text_input(f"Icon", value=risk_type['icon'], key=f"risk_icon_{i}")
                        new_description = st.text_area(f"Description", value=risk_type.get('description', ''), key=f"risk_desc_{i}")
                    
                    if st.button(f"Save {risk_type['name']}", key=f"save_risk_{i}"):
                        config['risk_types'][i]['name'] = new_name
                        config['risk_types'][i]['color'] = new_color
                        config['risk_types'][i]['icon'] = new_icon
                        config['risk_types'][i]['description'] = new_description
                        
                        if save_config(config):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                admin_email=admin_user['email'],
                                action="UPDATE_RISK_TYPE",
                                target_type="CONFIG",
                                details=f"Updated risk type: {new_name}"
                            )
                            st.success(f"Risk type '{new_name}' updated successfully!")
                            st.rerun()
            
            # Add new risk type
            st.markdown("**Add New Risk Type:**")
            with st.form("add_risk_type"):
                new_risk_name = st.text_input("Risk Type Name", placeholder="Enter new risk type...")
                new_risk_color = st.color_picker("Risk Color", "#6c757d")
                new_risk_icon = st.text_input("Risk Icon", placeholder="🚨")
                new_risk_description = st.text_area("Description", placeholder="Describe this risk type...")
                
                if st.form_submit_button("Add Risk Type"):
                    if new_risk_name:
                        new_risk = {
                            "name": new_risk_name,
                            "color": new_risk_color,
                            "icon": new_risk_icon,
                            "description": new_risk_description
                        }
                        config['risk_types'].append(new_risk)
                        
                        if save_config(config):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                admin_email=admin_user['email'],
                                action="ADD_RISK_TYPE",
                                target_type="CONFIG",
                                details=f"Added new risk type: {new_risk_name}"
                            )
                            st.success(f"Risk type '{new_risk_name}' added successfully!")
                            st.rerun()
                    else:
                        st.error("Please enter a risk type name.")
    
    with tab3:
        st.subheader("💡 Advice Templates Configuration")
        
        config = load_config()
        
        if config and 'advice_templates' in config:
            st.markdown("**Current Advice Templates:**")
            
            for risk_type, advice in config['advice_templates'].items():
                with st.expander(f"Advice for {risk_type}"):
                    st.markdown(advice)
                    
                    new_advice = st.text_area(
                        f"Edit advice for {risk_type}",
                        value=advice,
                        key=f"advice_{risk_type}"
                    )
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button(f"Save {risk_type} Advice", key=f"save_advice_{risk_type}"):
                            config['advice_templates'][risk_type] = new_advice
                            
                            if save_config(config):
                                log_admin_action(
                                    admin_id=admin_user['id'],
                                    admin_name=admin_user['full_name'],
                                    admin_email=admin_user['email'],
                                    action="UPDATE_ADVICE",
                                    target_type="CONFIG",
                                    details=f"Updated advice template for {risk_type}"
                                )
                                st.success(f"Advice for {risk_type} updated successfully!")
                                st.rerun()
                    
                    with col2:
                        if st.button(f"Reset {risk_type} Advice", key=f"reset_advice_{risk_type}"):
                            st.info(f"Reset functionality for {risk_type} will be implemented in the next version.")
    
    # Navigation
    st.subheader("⚡ Quick Navigation")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Admin Dashboard", type="secondary"):
            st.session_state.admin_page = "dashboard"
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