import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import folium
from streamlit_folium import folium_static
import json
import os
from pathlib import Path

# Data directory
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
STATE_ROADS_PATH = DATA_DIR / "state_roads.json"

# Nigeria's 36 states and FCT
NIGERIA_STATES = [
    "Abia", "Adamawa", "Akwa Ibom", "Anambra", "Bauchi", "Bayelsa", "Benue", "Borno",
    "Cross River", "Delta", "Ebonyi", "Edo", "Ekiti", "Enugu", "Gombe", "Imo", "Jigawa",
    "Kaduna", "Kano", "Katsina", "Kebbi", "Kogi", "Kwara", "Lagos", "Nasarawa", "Niger",
    "Ogun", "Ondo", "Osun", "Oyo", "Plateau", "Rivers", "Sokoto", "Taraba", "Yobe",
    "Zamfara", "FCT Abuja"
]

def _ensure_state_roads_file_exists():
    """Create the state_roads.json file if it's missing."""
    if not STATE_ROADS_PATH.exists():
        STATE_ROADS_PATH.write_text(json.dumps({}, ensure_ascii=False, indent=2), encoding="utf-8")

def load_state_roads():
    """Load mapping of state to list of major roads from disk."""
    _ensure_state_roads_file_exists()
    try:
        return json.loads(STATE_ROADS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_state_roads(mapping):
    """Persist mapping of state to major roads to disk."""
    try:
        STATE_ROADS_PATH.write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

def get_roads_for_state(state_name):
    """Return list of major roads for a given state, empty list if none registered."""
    mapping = load_state_roads()
    return mapping.get(state_name, [])

def add_roads_to_state(state_name, roads):
    """Add one or more roads to a state and persist them, deduplicated."""
    mapping = load_state_roads()
    existing = set(r.strip() for r in mapping.get(state_name, []) if r.strip())
    for road in roads:
        if road and road.strip():
            existing.add(road.strip())
    mapping[state_name] = sorted(existing)
    save_state_roads(mapping)

# Page configuration
st.set_page_config(
    page_title="Road Status Reporter - Minimal",
    page_icon="🚧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 0.5rem 0;
    }
    .status-pending { color: #ff7f0e; }
    .status-verified { color: #2ca02c; }
    .status-resolved { color: #d62728; }
    .risk-high { color: #d62728; font-weight: bold; }
    .risk-medium { color: #ff7f0e; font-weight: bold; }
    .risk-low { color: #2ca02c; font-weight: bold; }
    .admin-section {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Demo data for the minimal app
def get_demo_data():
    """Generate demo data for the minimal app"""
    # Nigerian states and LGAs
    states = {
        "Lagos": ["Victoria Island", "Ikeja", "Surulere", "Alimosho", "Oshodi", "Mushin"],
        "Kano": ["Municipal", "Fagge", "Dala", "Gwale", "Tarauni", "Ungogo"],
        "Rivers": ["Port Harcourt", "Okrika", "Eleme", "Ikwerre", "Emohua", "Obio-Akpor"],
        "Kaduna": ["Kaduna North", "Kaduna South", "Chikun", "Igabi", "Kachia", "Kauru"],
        "Katsina": ["Katsina", "Daura", "Funtua", "Malumfashi", "Kankia", "Mani"]
    }
    
    # Road conditions
    road_conditions = ["Potholes", "Flooding", "Landslide", "Construction", "Accident", "Traffic Jam"]
    risk_levels = ["High", "Medium", "Low"]
    statuses = ["Pending", "Verified", "Resolved"]
    
    # Generate demo reports
    reports = []
    for i in range(25):
        state = list(states.keys())[i % len(states)]
        lga = states[state][i % len(states[state])]
        
        report = {
            "id": i + 1,
            "title": f"Road Issue in {lga}, {state}",
            "description": f"Reported road condition issue in {lga} area of {state} state.",
            "location": f"{lga}, {state}",
            "latitude": 6.5244 + (i * 0.01),  # Around Lagos coordinates
            "longitude": 3.3792 + (i * 0.01),
            "risk_level": risk_levels[i % len(risk_levels)],
            "road_condition": road_conditions[i % len(road_conditions)],
            "status": statuses[i % len(statuses)],
            "user": f"User_{i + 1}",
            "created_at": (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d"),
            "votes": i + 5,
            "comments": i + 2
        }
        reports.append(report)
    
    return reports

# Demo admin data
def get_demo_admin_data():
    """Generate demo admin data"""
    return {
        "users": [
            {"id": 1, "username": "user1", "email": "user1@example.com", "status": "active", "reports": 5},
            {"id": 2, "username": "user2", "email": "user2@example.com", "status": "active", "reports": 3},
            {"id": 3, "username": "user3", "email": "user3@example.com", "status": "suspended", "reports": 1},
        ],
        "admin_logs": [
            {"timestamp": "2024-01-15 10:30:00", "admin": "admin1", "action": "verified_report", "target": "Report #15"},
            {"timestamp": "2024-01-15 09:15:00", "admin": "admin2", "action": "suspended_user", "target": "User #3"},
            {"timestamp": "2024-01-14 16:45:00", "admin": "admin1", "action": "resolved_report", "target": "Report #8"},
        ]
    }

def main():
    """Main application function"""
    st.markdown('<h1 class="main-header">🚧 Road Status Reporter - Minimal</h1>', unsafe_allow_html=True)
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    
    # Check if user is admin
    if "is_admin" not in st.session_state:
        st.session_state.is_admin = False
    
    # Auth state
    if "user_authenticated" not in st.session_state:
        st.session_state.user_authenticated = False
    if "username" not in st.session_state:
        st.session_state.username = ""
    if "_registered_users" not in st.session_state:
        st.session_state._registered_users = {}

    # Navigation options (Public Feed always available)
    nav_options = [
        "Public Feed",
        "Verified Driver Reports",
        "Dashboard",
        "Reports",
        "Create Report",
        "Map View",
        "Analytics",
        "Login / Signup"
    ]
    if st.session_state.is_admin:
        nav_options.append("Admin Panel")

    page = st.sidebar.selectbox("Choose a page:", nav_options)

    # Routing
    if page == "Public Feed":
        show_public_feed()
    elif page == "Verified Driver Reports":
        if st.session_state.user_authenticated:
            show_verified_reports_page()
        else:
            st.warning("Please log in to view verified driver reports.")
            show_login_page()
    elif page == "Dashboard":
        show_dashboard()
    elif page == "Reports":
        show_reports_page()
    elif page == "Create Report":
        show_create_report_page()
    elif page == "Map View":
        show_map_view()
    elif page == "Analytics":
        show_analytics_page()
    elif page == "Login / Signup":
        show_signup_page()
    elif page == "Admin Panel" and st.session_state.is_admin:
        show_admin_panel()

    # Sidebar auth controls
    if st.session_state.user_authenticated:
        st.sidebar.markdown(f"Logged in as **{st.session_state.username}**")
        if st.sidebar.button("Logout"):
            st.session_state.user_authenticated = False
            st.session_state.is_admin = False
            st.session_state.username = ""
            st.rerun()
    else:
        st.sidebar.info("Viewing public feed. Login for verified reports.")
        

def show_login_page():
    """Show login page"""
    st.markdown("## 🔐 Login")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                # Simple demo authentication
                if username and password:
                    st.session_state.user_authenticated = True
                    st.session_state.username = username
                    
                    # Check if user is admin (demo: admin/admin)
                    if username.lower() == "admin" and password == "admin":
                        st.session_state.is_admin = True
                        st.success("🔑 Admin access granted!")
                    else:
                        st.session_state.is_admin = False
                        st.success("✅ Login successful!")
                    
                    st.rerun()
                else:
                    st.error("Please enter both username and password")
        
        st.info("💡 **Demo Mode**: Enter any username and password to continue")
        st.info("🔑 **Admin Access**: Use 'admin/admin' for admin features")

def show_signup_page():
    """Signup/Login combined page for demo purposes."""
    st.markdown("## 🔐 Login / ✍️ Signup")
    login_tab, signup_tab = st.tabs(["Login", "Signup"])

    with login_tab:
        show_login_page()

    with signup_tab:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.form("signup_form"):
                su_username = st.text_input("Choose Username")
                su_password = st.text_input("Choose Password", type="password")
                su_confirm = st.text_input("Confirm Password", type="password")
                submit_su = st.form_submit_button("Create Account")
                if submit_su:
                    if not su_username or not su_password:
                        st.error("Username and password are required.")
                    elif su_password != su_confirm:
                        st.error("Passwords do not match.")
                    else:
                        st.session_state._registered_users[su_username.lower()] = su_password
                        st.session_state.user_authenticated = True
                        st.session_state.username = su_username
                        st.success("🎉 Account created and logged in!")
                        st.rerun()

def show_dashboard():
    """Show main dashboard"""
    st.markdown("## 📊 Dashboard Overview")
    
    # Get demo data
    reports = get_demo_data()
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Reports", len(reports))
    
    with col2:
        pending_count = len([r for r in reports if r["status"] == "Pending"])
        st.markdown(f'<div class="metric-card">Pending Reports: <span class="status-pending">{pending_count}</span></div>', unsafe_allow_html=True)
    
    with col3:
        verified_count = len([r for r in reports if r["status"] == "Verified"])
        st.markdown(f'<div class="metric-card">Verified Reports: <span class="status-verified">{verified_count}</span></div>', unsafe_allow_html=True)
    
    with col4:
        resolved_count = len([r for r in reports if r["status"] == "Resolved"])
        st.markdown(f'<div class="metric-card">Resolved Reports: <span class="status-resolved">{resolved_count}</span></div>', unsafe_allow_html=True)
    
    # Recent reports
    st.markdown("### 📋 Recent Reports")
    recent_reports = reports[:5]
    
    for report in recent_reports:
        with st.container():
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                st.markdown(f"**{report['title']}**")
                st.markdown(f"📍 {report['location']}")
                st.markdown(f"🔧 {report['road_condition']}")
            
            with col2:
                risk_class = f"risk-{report['risk_level'].lower()}"
                st.markdown(f'<span class="{risk_class}">{report["risk_level"]} Risk</span>', unsafe_allow_html=True)
            
            with col3:
                status_class = f"status-{report['status'].lower()}"
                st.markdown(f'<span class="{status_class}">{report["status"]}</span>', unsafe_allow_html=True)
            
            st.divider()

def show_reports_page():
    """Show all reports page"""
    st.markdown("## 📋 All Reports")
    
    reports = get_demo_data()
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox("Filter by Status", ["All"] + list(set(r["status"] for r in reports)))
    
    with col2:
        risk_filter = st.selectbox("Filter by Risk Level", ["All"] + list(set(r["risk_level"] for r in reports)))
    
    with col3:
        search = st.text_input("Search reports...")
    
    # Apply filters
    filtered_reports = reports
    if status_filter != "All":
        filtered_reports = [r for r in filtered_reports if r["status"] == status_filter]
    
    if risk_filter != "All":
        filtered_reports = [r for r in filtered_reports if r["risk_level"] == risk_filter]
    
    if search:
        filtered_reports = [r for r in filtered_reports if search.lower() in r["title"].lower() or search.lower() in r["location"].lower()]
    
    # Display reports
    st.markdown(f"**Showing {len(filtered_reports)} reports**")
    
    for report in filtered_reports:
        with st.expander(f"{report['title']} - {report['location']}"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Description:** {report['description']}")
                st.markdown(f"**Road Condition:** {report['road_condition']}")
                st.markdown(f"**Created:** {report['created_at']}")
                st.markdown(f"**User:** {report['user']}")
            
            with col2:
                risk_class = f"risk-{report['risk_level'].lower()}"
                st.markdown(f'<span class="{risk_class}">{report["risk_level"]} Risk</span>', unsafe_allow_html=True)
                
                status_class = f"status-{report['status'].lower()}"
                st.markdown(f'<span class="{status_class}">{report["status"]}</span>', unsafe_allow_html=True)
                
                st.markdown(f"👍 {report['votes']} votes")
                st.markdown(f"💬 {report['comments']} comments")
            
            # Admin actions (if user is admin)
            if st.session_state.is_admin:
                st.markdown("---")
                st.markdown("**🔧 Admin Actions:**")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button(f"Verify #{report['id']}", key=f"verify_{report['id']}"):
                        st.success(f"Report #{report['id']} verified!")
                
                with col2:
                    if st.button(f"Resolve #{report['id']}", key=f"resolve_{report['id']}"):
                        st.success(f"Report #{report['id']} resolved!")
                
                with col3:
                    if st.button(f"Delete #{report['id']}", key=f"delete_{report['id']}"):
                        st.success(f"Report #{report['id']} deleted!")

def show_verified_reports_page():
    """Show only verified driver reports (requires login)."""
    st.markdown("## ✅ Verified Driver Reports")
    reports = [r for r in get_demo_data() if r["status"] == "Verified"]
    if not reports:
        st.info("No verified reports available yet.")
        return
    for report in reports:
        with st.expander(f"{report['title']} - {report['location']}"):
            st.markdown(f"**Verified:** Yes")
            st.markdown(f"**Description:** {report['description']}")
            st.markdown(f"**Risk:** {report['risk_level']}")
            st.markdown(f"**Date:** {report['created_at']}")

def show_public_feed():
    """Public social-media-like feed available without login."""
    st.markdown("## 📰 Public Feed")
    st.caption("General community-submitted road status posts. Verified driver reports require login.")
    reports = get_demo_data()[:10]
    for report in reports:
        with st.container():
            st.markdown(f"**{report['title']}** — {report['location']}")
            st.markdown(f"{report['description']}")
            meta = f"{report['created_at']} • {report['road_condition']} • {report['risk_level']} risk"
            st.caption(meta)
            st.divider()

def show_create_report_page():
    """Show create report page"""
    st.markdown("## 📝 Create New Report")
    
    with st.form("create_report_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            title = st.text_input("Report Title *")
            description = st.text_area("Description *")
            # Location selection: State and Road
            state = st.selectbox("State (36 + FCT) *", NIGERIA_STATES, index=NIGERIA_STATES.index("Lagos"))
            available_roads = get_roads_for_state(state)
            if available_roads:
                road = st.selectbox("Major Road (auto from selected state)", available_roads, index=0)
            else:
                st.info("No major roads recorded for this state yet. Add below to proceed.")
                road = ""
            
            road_condition = st.selectbox("Road Condition *", [
                "Potholes", "Flooding", "Landslide", "Construction", 
                "Accident", "Traffic Jam", "Other"
            ])
        
        with col2:
            latitude = st.number_input("Latitude *", value=6.5244, format="%.4f")
            longitude = st.number_input("Longitude *", value=3.3792, format="%.4f")
            risk_level = st.selectbox("Risk Level *", ["Low", "Medium", "High"])
            category = st.selectbox("Category", [
                "Road Safety", "Infrastructure", "Traffic", "Environment", "Other"
            ])
        
        # Allow adding roads for a state if none exist or to extend the list
        with st.expander("Manage major roads for selected state"):
            st.markdown("Provide a comma-separated list of major roads. Keep names concise and accurate.")
            new_roads_csv = st.text_input("Add/Update roads for {}".format(state), placeholder="e.g., Ikorodu Road, Badagry Expressway")
            if st.form_submit_button("Save Roads for State"):
                new_roads = [r.strip() for r in new_roads_csv.split(",") if r.strip()]
                if new_roads:
                    add_roads_to_state(state, new_roads)
                    st.success("Saved roads for {}".format(state))
                    st.session_state["_roads_updated_ts"] = datetime.now().isoformat()
                    st.rerun()
                else:
                    st.warning("Please enter at least one road name before saving.")

        # File upload
        uploaded_files = st.file_uploader(
            "Upload Images (optional)",
            type=["jpg", "jpeg", "png"],
            accept_multiple_files=True
        )
        
        submit = st.form_submit_button("Submit Report")
        
        if submit:
            # Build location string from state and road (if provided)
            location_str = f"{road}, {state}" if road else state
            if title and description and state:
                st.success("✅ Report submitted successfully!")
                st.balloons()
            else:
                st.error("Please fill in all required fields (*)")

def show_map_view():
    """Show interactive map view"""
    st.markdown("## 🗺️ Interactive Map View")
    
    reports = get_demo_data()
    
    # Create map centered on Nigeria
    m = folium.Map(
        location=[9.0820, 8.6753],  # Center of Nigeria
        zoom_start=6,
        tiles="OpenStreetMap"
    )
    
    # Add markers for each report
    for report in reports:
        # Color based on risk level
        if report["risk_level"] == "High":
            color = "red"
        elif report["risk_level"] == "Medium":
            color = "orange"
        else:
            color = "green"
        
        # Popup content
        popup_content = f"""
        <div style="width: 200px;">
            <h4>{report['title']}</h4>
            <p><strong>Location:</strong> {report['location']}</p>
            <p><strong>Risk Level:</strong> {report['risk_level']}</p>
            <p><strong>Status:</strong> {report['status']}</p>
            <p><strong>Road Condition:</strong> {report['road_condition']}</p>
        </div>
        """
        
        folium.Marker(
            location=[report["latitude"], report["longitude"]],
            popup=folium.Popup(popup_content, max_width=300),
            tooltip=report["title"],
            icon=folium.Icon(color=color, icon="info-sign")
        ).add_to(m)
    
    # Display map
    folium_static(m, width=800, height=600)
    
    # Map legend
    st.markdown("### Map Legend")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("🔴 **High Risk**")
    with col2:
        st.markdown("🟠 **Medium Risk**")
    with col3:
        st.markdown("🟢 **Low Risk**")

def show_analytics_page():
    """Show analytics page"""
    st.markdown("## 📈 Analytics & Insights")
    
    reports = get_demo_data()
    
    # Convert to DataFrame for analysis
    df = pd.DataFrame(reports)
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Reports by Status")
        status_counts = df["status"].value_counts()
        fig = px.pie(
            values=status_counts.values,
            names=status_counts.index,
            title="Report Status Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Reports by Risk Level")
        risk_counts = df["risk_level"].value_counts()
        fig = px.bar(
            x=risk_counts.index,
            y=risk_counts.values,
            title="Reports by Risk Level",
            color=risk_counts.index,
            color_discrete_map={"High": "#d62728", "Medium": "#ff7f0e", "Low": "#2ca02c"}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Time series
    st.markdown("### Reports Over Time")
    df["created_at"] = pd.to_datetime(df["created_at"])
    daily_counts = df.groupby("created_at").size().reset_index(name="count")
    
    fig = px.line(
        daily_counts,
        x="created_at",
        y="count",
        title="Daily Report Count",
        markers=True
    )
    fig.update_layout(xaxis_title="Date", yaxis_title="Number of Reports")
    st.plotly_chart(fig, use_container_width=True)
    
    # Summary statistics
    st.markdown("### Summary Statistics")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Reports", len(reports))
    with col2:
        st.metric("High Risk Reports", len(df[df["risk_level"] == "High"]))
    with col3:
        st.metric("Pending Reports", len(df[df["status"] == "Pending"]))
    with col4:
        st.metric("Avg Votes per Report", round(df["votes"].mean(), 1))

def show_admin_panel():
    """Show admin panel"""
    st.markdown("## 🔧 Admin Panel")
    
    if not st.session_state.is_admin:
        st.error("Access denied. Admin privileges required.")
        return
    
    st.markdown('<div class="admin-section">🔑 **Admin Access Granted** - You can view all logs and manage users</div>', unsafe_allow_html=True)
    
    # Admin tabs
    tab1, tab2, tab3 = st.tabs(["👥 User Management", "📊 System Logs", "⚙️ Settings"])
    
    with tab1:
        st.markdown("### User Management")
        admin_data = get_demo_admin_data()
        
        # Display users
        for user in admin_data["users"]:
            with st.expander(f"User: {user['username']} ({user['email']})"):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    st.markdown(f"**Status:** {user['status']}")
                    st.markdown(f"**Reports Created:** {user['reports']}")
                
                with col2:
                    if user['status'] == 'active':
                        if st.button(f"Suspend {user['username']}", key=f"suspend_{user['id']}"):
                            st.success(f"User {user['username']} suspended!")
                    else:
                        if st.button(f"Activate {user['username']}", key=f"activate_{user['id']}"):
                            st.success(f"User {user['username']} activated!")
                
                with col3:
                    if st.button(f"View Logs {user['username']}", key=f"logs_{user['id']}"):
                        st.info(f"Showing logs for {user['username']}")
                        # In a real app, this would fetch user logs
                        st.write("User activity logs would be displayed here...")
    
    with tab2:
        st.markdown("### System Logs")
        admin_data = get_demo_admin_data()
        
        # Display admin logs
        st.markdown("**Recent Admin Actions:**")
        for log in admin_data["admin_logs"]:
            st.markdown(f"**{log['timestamp']}** - {log['admin']} {log['action']} on {log['target']}")
        
        # Super admin can see all logs
        if st.session_state.username.lower() == "admin":
            st.markdown("---")
            st.markdown("**🔍 Super Admin - All System Logs:**")
            st.markdown("As a super admin, you can view all system logs including:")
            st.markdown("- User activity logs")
            st.markdown("- Report moderation logs")
            st.markdown("- System configuration changes")
            st.markdown("- Admin action logs")
            
            if st.button("View All Logs"):
                st.info("All system logs would be displayed here...")
                st.write("This would show comprehensive system activity in a real application.")
    
    with tab3:
        st.markdown("### Admin Settings")
        st.markdown("**System Configuration:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.number_input("Max Reports per User", value=10, min_value=1, max_value=100)
            st.number_input("Auto-suspend Threshold", value=5, min_value=1, max_value=20)
            st.selectbox("Default Report Status", ["Pending", "Verified", "Resolved"])
        
        with col2:
            st.checkbox("Enable Auto-moderation", value=True)
            st.checkbox("Require Admin Approval", value=False)
            st.checkbox("Log All User Actions", value=True)
        
        if st.button("Save Settings"):
            st.success("Settings saved successfully!")

if __name__ == "__main__":
    main()
