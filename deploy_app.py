#!/usr/bin/env python3
"""
Deployment Module for Nigerian Road Risk Reporter
PWA configuration, SMS fallback, and Streamlit Cloud deployment
Python 3.13 compatible - Streamlit Cloud ready
"""

import streamlit as st
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

# PWA Configuration
PWA_CONFIG = {
    "name": "Nigerian Road Risk Reporter",
    "short_name": "RoadRisk",
    "description": "Real-time road risk reporting for Nigeria",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#ffffff",
    "theme_color": "#1f77b4",
    "icons": [
        {
            "src": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTkyIiBoZWlnaHQ9IjE5MiIgdmlld0JveD0iMCAwIDE5MiAxOTIiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxOTIiIGhlaWdodD0iMTkyIiByeD0iMjQiIGZpbGw9IiMxZjc3YjQiLz4KPHN2ZyB4PSI0OCIgeT0iNDgiIHdpZHRoPSI5NiIgaGVpZ2h0PSI5NiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+CjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyeiIvPgo8cGF0aCBkPSJNMTIgNkM4LjY5IDYgNiA4LjY5IDYgMTJzMi42OSA2IDYgNiA2LTIuNjkgNi02LTIuNjktNi02LTZ6Ii8+Cjwvc3ZnPgo8L3N2Zz4K",
            "sizes": "192x192",
            "type": "image/svg+xml"
        }
    ]
}

# SMS Configuration
SMS_CONFIG = {
    "enabled": True,
    "admin_numbers": ["+2348012345678", "+2348098765432"],
    "emergency_numbers": ["112", "0800-112-1199"],
    "templates": {
        "new_report": "🚨 New Risk Report: {risk_type} at {location}. Report ID: {report_id}",
        "high_risk": "⚠️ HIGH RISK ALERT: {risk_type} at {location}. Immediate attention required!",
        "resolved": "✅ Risk Resolved: Report #{report_id} at {location} has been resolved."
    }
}

def create_manifest_json() -> str:
    """Create PWA manifest.json content"""
    try:
        return json.dumps(PWA_CONFIG, indent=2)
    except Exception as e:
        st.error(f"Failed to create manifest.json: {str(e)}")
        return "{}"

def create_service_worker() -> str:
    """Create basic service worker for PWA functionality"""
    try:
        sw_content = """
// Service Worker for Road Risk Reporter PWA
const CACHE_NAME = 'road-risk-reporter-v1';
const urlsToCache = [
  '/',
  '/static/css/main.css',
  '/static/js/main.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      })
  );
});

self.addEventListener('push', (event) => {
  const options = {
    body: event.data.text(),
    icon: '/icon-192x192.png',
    badge: '/badge-72x72.png',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    }
  };
  
  event.waitUntil(
    self.registration.showNotification('Road Risk Alert', options)
  );
});
"""
        return sw_content
    except Exception as e:
        st.error(f"Failed to create service worker: {str(e)}")
        return ""

def simulate_sms_alert(risk_type: str, location: str, report_id: int, alert_type: str = "new_report") -> bool:
    """Simulate SMS alert sending"""
    try:
        if not SMS_CONFIG["enabled"]:
            return False
        
        # Get template
        template = SMS_CONFIG["templates"].get(alert_type, SMS_CONFIG["templates"]["new_report"])
        
        # Format message
        message = template.format(
            risk_type=risk_type,
            location=location,
            report_id=report_id
        )
        
        # Simulate sending to admin numbers
        for number in SMS_CONFIG["admin_numbers"]:
            print(f"SMS sent to {number}: {message}")
        
        # Log the SMS simulation
        st.info(f"📱 SMS Alert Simulated: {message}")
        
        return True
        
    except Exception as e:
        st.error(f"Failed to send SMS alert: {str(e)}")
        return False

def create_streamlit_config() -> str:
    """Create Streamlit configuration for deployment"""
    try:
        config_content = """
[theme]
primaryColor = "#1f77b4"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
font = "sans serif"

[server]
headless = true
port = 8501
enableCORS = false
enableXsrfProtection = false

[browser]
gatherUsageStats = false

[client]
showErrorDetails = true
"""
        return config_content
    except Exception as e:
        st.error(f"Failed to create Streamlit config: {str(e)}")
        return ""

def create_procfile() -> str:
    """Create Procfile for Render deployment"""
    try:
        return "web: streamlit run streamlit_app_minimal.py --server.port=\$PORT --server.address=0.0.0.0"
    except Exception as e:
        st.error(f"Failed to create Procfile: {str(e)}")
        return ""

def create_gitignore() -> str:
    """Create .gitignore for deployment"""
    try:
        gitignore_content = """
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Streamlit
.streamlit/secrets.toml

# Database
*.db
*.sqlite
*.sqlite3

# Logs
*.log

# Environment variables
.env
.env.local

# Uploads
uploads/
temp/

# Cache
.cache/
"""
        return gitignore_content
    except Exception as e:
        st.error(f"Failed to create .gitignore: {str(e)}")
        return ""

def create_deployment_readme() -> str:
    """Create deployment README"""
    try:
        readme_content = """
# Road Risk Reporter - Deployment Guide

## Streamlit Cloud Deployment

1. **Fork/Clone Repository**
   ```bash
   git clone <repository-url>
   cd V8_Road_Status_Report
   ```

2. **Deploy to Streamlit Cloud**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Connect your GitHub repository
   - Set main file: `streamlit_app_minimal.py`
   - Deploy!

3. **Environment Variables**
   - `ENCRYPTION_KEY`: (Optional) For data encryption
   - `ADMIN_EMAIL`: Admin email for notifications
   - `SMS_API_KEY`: (Optional) For SMS notifications

## Local Development

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Application**
   ```bash
   streamlit run streamlit_app_minimal.py
   ```

3. **Access Application**
   - Open browser to `http://localhost:8501`

## PWA Features

- **Offline Support**: Basic caching for core functionality
- **Push Notifications**: Real-time alerts for new reports
- **App-like Experience**: Full-screen mode and native feel

## SMS Integration

- **Simulated SMS**: Currently simulates SMS alerts
- **Real SMS**: Can be integrated with Twilio, AWS SNS, or similar
- **Admin Notifications**: Automatic alerts for high-risk reports

## Security Features

- **Data Encryption**: Optional encryption for sensitive data
- **RBAC**: Role-based access control
- **CAPTCHA**: Protection against automated submissions
- **Session Management**: Secure user sessions

## Troubleshooting

1. **Database Issues**: Ensure `users.db` is writable
2. **Import Errors**: Check Python version compatibility (3.13+)
3. **Deployment Failures**: Verify requirements.txt compatibility
4. **PWA Issues**: Check browser console for service worker errors

## Support

For issues and questions:
- Check the main README.md
- Review error logs in Streamlit Cloud
- Ensure all dependencies are compatible
"""
        return readme_content
    except Exception as e:
        st.error(f"Failed to create deployment README: {str(e)}")
        return ""

def display_deployment_interface():
    """Display deployment configuration interface"""
    st.markdown("## 🚀 Deployment Configuration")
    
    # PWA Configuration
    with st.expander("📱 PWA Configuration", expanded=False):
        st.markdown("### Progressive Web App Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            PWA_CONFIG["name"] = st.text_input("App Name", value=PWA_CONFIG["name"])
            PWA_CONFIG["short_name"] = st.text_input("Short Name", value=PWA_CONFIG["short_name"])
            PWA_CONFIG["description"] = st.text_area("Description", value=PWA_CONFIG["description"])
        
        with col2:
            PWA_CONFIG["background_color"] = st.color_picker("Background Color", value=PWA_CONFIG["background_color"])
            PWA_CONFIG["theme_color"] = st.color_picker("Theme Color", value=PWA_CONFIG["theme_color"])
            PWA_CONFIG["display"] = st.selectbox("Display Mode", ["standalone", "fullscreen", "minimal-ui", "browser"], index=0)
        
        # Generate manifest.json
        if st.button("Generate manifest.json"):
            manifest_content = create_manifest_json()
            st.download_button(
                label="📄 Download manifest.json",
                data=manifest_content,
                file_name="manifest.json",
                mime="application/json"
            )
            st.code(manifest_content, language="json")
    
    # SMS Configuration
    with st.expander("📱 SMS Configuration", expanded=False):
        st.markdown("### SMS Alert Settings")
        
        SMS_CONFIG["enabled"] = st.checkbox("Enable SMS Alerts", value=SMS_CONFIG["enabled"])
        
        if SMS_CONFIG["enabled"]:
            admin_numbers = st.text_area(
                "Admin Phone Numbers (one per line)",
                value="\n".join(SMS_CONFIG["admin_numbers"]),
                help="Enter phone numbers in international format (+234...)"
            )
            SMS_CONFIG["admin_numbers"] = [num.strip() for num in admin_numbers.split("\n") if num.strip()]
            
            # Test SMS
            if st.button("Test SMS Alert"):
                if simulate_sms_alert("Test", "Test Location", 999, "new_report"):
                    st.success("✅ SMS test completed successfully!")
    
    # Deployment Files
    with st.expander("📁 Deployment Files", expanded=False):
        st.markdown("### Generate Deployment Files")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Generate Streamlit Config"):
                config_content = create_streamlit_config()
                st.download_button(
                    label="📄 Download .streamlit/config.toml",
                    data=config_content,
                    file_name="config.toml",
                    mime="text/plain"
                )
                st.code(config_content, language="toml")
            
            if st.button("Generate Procfile"):
                procfile_content = create_procfile()
                st.download_button(
                    label="📄 Download Procfile",
                    data=procfile_content,
                    file_name="Procfile",
                    mime="text/plain"
                )
                st.code(procfile_content, language="text")
        
        with col2:
            if st.button("Generate .gitignore"):
                gitignore_content = create_gitignore()
                st.download_button(
                    label="📄 Download .gitignore",
                    data=gitignore_content,
                    file_name=".gitignore",
                    mime="text/plain"
                )
                st.code(gitignore_content, language="text")
            
            if st.button("Generate Service Worker"):
                sw_content = create_service_worker()
                st.download_button(
                    label="📄 Download service-worker.js",
                    data=sw_content,
                    file_name="service-worker.js",
                    mime="application/javascript"
                )
                st.code(sw_content, language="javascript")

def display_deployment_status():
    """Display deployment status and health check"""
    st.markdown("## 📊 Deployment Status")
    
    # Health check
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("### 🔧 System Health")
        
        # Check Python version
        import sys
        python_version = sys.version_info
        if python_version.major == 3 and python_version.minor >= 13:
            st.success(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
        else:
            st.warning(f"⚠️ Python {python_version.major}.{python_version.minor}.{python_version.micro} (3.13+ recommended)")
        
        # Check database
        try:
            import sqlite3
            conn = sqlite3.connect('users.db')
            conn.close()
            st.success("✅ Database connection")
        except Exception:
            st.error("❌ Database connection failed")
        
        # Check dependencies
        try:
            import streamlit
            st.success(f"✅ Streamlit {streamlit.__version__}")
        except Exception:
            st.error("❌ Streamlit not available")
    
    with col2:
        st.markdown("### 📱 PWA Status")
        
        if os.path.exists("manifest.json"):
            st.success("✅ manifest.json found")
        else:
            st.info("ℹ️ manifest.json not found")
        
        if os.path.exists("service-worker.js"):
            st.success("✅ service-worker.js found")
        else:
            st.info("ℹ️ service-worker.js not found")
        
        st.info(f"ℹ️ PWA Mode: {PWA_CONFIG['display']}")
    
    with col3:
        st.markdown("### 📱 SMS Status")
        
        if SMS_CONFIG["enabled"]:
            st.success("✅ SMS alerts enabled")
            st.info(f"📞 {len(SMS_CONFIG['admin_numbers'])} admin numbers")
        else:
            st.warning("⚠️ SMS alerts disabled")
        
        st.info("ℹ️ Currently simulating SMS")

def display_deployment_guide():
    """Display deployment guide"""
    st.markdown("## 📖 Deployment Guide")
    
    with st.expander("🚀 Quick Deploy to Streamlit Cloud", expanded=False):
        st.markdown("""
        ### Step 1: Prepare Your Repository
        1. Ensure all files are committed to GitHub
        2. Verify `requirements.txt` is compatible with Streamlit Cloud
        3. Check that `streamlit_app_minimal.py` is the main entry point
        
        ### Step 2: Deploy to Streamlit Cloud
        1. Go to [share.streamlit.io](https://share.streamlit.io)
        2. Sign in with GitHub
        3. Click "New app"
        4. Select your repository and branch
        5. Set main file: `streamlit_app_minimal.py`
        6. Click "Deploy!"
        
        ### Step 3: Configure Environment (Optional)
        - Add environment variables in Streamlit Cloud dashboard
        - Set `ENCRYPTION_KEY` for data encryption
        - Configure admin email for notifications
        """)
    
    with st.expander("🔧 Advanced Configuration", expanded=False):
        st.markdown("""
        ### PWA Configuration
        - Place `manifest.json` in your repository root
        - Add service worker for offline functionality
        - Configure app icons and colors
        
        ### SMS Integration
        - Currently simulates SMS alerts
        - Can be integrated with Twilio, AWS SNS, or similar
        - Configure webhook endpoints for real SMS
        
        ### Security Setup
        - Generate encryption keys for production
        - Configure admin accounts
        - Set up monitoring and logging
        """)
    
    with st.expander("🐛 Troubleshooting", expanded=False):
        st.markdown("""
        ### Common Issues
        
        **Deployment Fails:**
        - Check Python version compatibility (3.13+)
        - Verify all dependencies in requirements.txt
        - Ensure no deprecated packages (distutils, rich>=14)
        
        **Database Errors:**
        - Streamlit Cloud uses read-only filesystem
        - Use external database (PostgreSQL, MySQL) for production
        - SQLite works for development only
        
        **Import Errors:**
        - Check for missing dependencies
        - Verify package versions are compatible
        - Use fallback imports where possible
        
        **PWA Not Working:**
        - Check browser console for errors
        - Verify manifest.json is valid
        - Ensure HTTPS is enabled (required for PWA)
        """)

def main():
    """Main function for deployment module"""
    st.set_page_config(
        page_title="Deployment Module",
        page_icon="🚀",
        layout="wide"
    )
    
    st.title("🚀 Deployment Module")
    st.markdown("PWA configuration, SMS integration, and deployment tools for Road Risk Reporter")
    
    # Display deployment interface
    display_deployment_interface()
    
    # Display deployment status
    display_deployment_status()
    
    # Display deployment guide
    display_deployment_guide()
    
    # Generate all files
    with st.expander("📦 Generate All Deployment Files", expanded=False):
        if st.button("Generate All Files"):
            try:
                # Create files
                manifest_content = create_manifest_json()
                sw_content = create_service_worker()
                config_content = create_streamlit_config()
                procfile_content = create_procfile()
                gitignore_content = create_gitignore()
                readme_content = create_deployment_readme()
                
                # Create zip-like download
                all_files = f"""
=== manifest.json ===
{manifest_content}

=== service-worker.js ===
{sw_content}

=== .streamlit/config.toml ===
{config_content}

=== Procfile ===
{procfile_content}

=== .gitignore ===
{gitignore_content}

=== DEPLOYMENT_README.md ===
{readme_content}
"""
                
                st.download_button(
                    label="📦 Download All Files",
                    data=all_files,
                    file_name="deployment_files.txt",
                    mime="text/plain"
                )
                
                st.success("✅ All deployment files generated successfully!")
                
            except Exception as e:
                st.error(f"Failed to generate files: {str(e)}")

if __name__ == "__main__":
    main() 