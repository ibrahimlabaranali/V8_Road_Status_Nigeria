#!/usr/bin/env python3
"""
Deployment Module for Nigerian Road Risk Reporter
PWA features, SMS fallback, and deployment instructions
"""

import streamlit as st
import sqlite3
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# PWA Configuration
PWA_CONFIG = {
    'app_name': 'Nigerian Road Risk Reporter',
    'short_name': 'RoadRisk',
    'description': 'Real-time road risk reporting for Nigeria',
    'theme_color': '#1f77b4',
    'background_color': '#ffffff',
    'display': 'standalone',
    'start_url': '/',
    'scope': '/',
    'icons': [
        {
            'src': '/static/icon-192x192.png',
            'sizes': '192x192',
            'type': 'image/png'
        },
        {
            'src': '/static/icon-512x512.png',
            'sizes': '512x512',
            'type': 'image/png'
        }
    ]
}

class SMSFallback:
    """SMS and WhatsApp fallback communication system"""
    
    @staticmethod
    def send_high_risk_alert(report_data: Dict):
        """Send alert for high-risk reports"""
        try:
            risk_type = report_data.get('risk_type', 'Unknown')
            location = report_data.get('location', 'Unknown location')
            
            if risk_type.lower() == 'robbery':
                message = f"🚨 URGENT: Robbery reported at {location}. Avoid area immediately."
                SMSFallback._log_alert('ROBBERY_ALERT', message, report_data)
                
                # Simulate admin notification
                SMSFallback._notify_admin(message, report_data)
                
            elif risk_type.lower() in ['flooding', 'protest']:
                message = f"⚠️ ALERT: {risk_type.title()} reported at {location}. Exercise caution."
                SMSFallback._log_alert('RISK_ALERT', message, report_data)
            
            return True
            
        except Exception as e:
            st.error(f"Error sending SMS alert: {str(e)}")
            return False
    
    @staticmethod
    def _log_alert(alert_type: str, message: str, report_data: Dict):
        """Log alert to database"""
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            # Create alerts table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sms_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    report_id INTEGER,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'sent'
                )
            ''')
            
            cursor.execute('''
                INSERT INTO sms_alerts (alert_type, message, report_id)
                VALUES (?, ?, ?)
            ''', (alert_type, message, report_data.get('id')))
            
            conn.commit()
            conn.close()
            
            # Print to console for simulation
            print(f"[SMS ALERT] {datetime.now()}: {message}")
            
        except Exception as e:
            st.error(f"Error logging alert: {str(e)}")
    
    @staticmethod
    def _notify_admin(message: str, report_data: Dict):
        """Notify admin of critical alerts"""
        try:
            # Simulate admin notification
            admin_message = f"ADMIN ALERT: {message}\nReport ID: {report_data.get('id')}\nLocation: {report_data.get('location')}"
            print(f"[ADMIN NOTIFICATION] {datetime.now()}: {admin_message}")
            
            # In a real implementation, this would send to admin dashboard or email
            st.session_state.admin_alerts = st.session_state.get('admin_alerts', []) + [{
                'message': admin_message,
                'timestamp': datetime.now().isoformat(),
                'report_id': report_data.get('id')
            }]
            
        except Exception as e:
            st.error(f"Error notifying admin: {str(e)}")

class PWAManager:
    """Progressive Web App features manager"""
    
    @staticmethod
    def generate_manifest() -> str:
        """Generate PWA manifest.json"""
        manifest = {
            "name": PWA_CONFIG['app_name'],
            "short_name": PWA_CONFIG['short_name'],
            "description": PWA_CONFIG['description'],
            "theme_color": PWA_CONFIG['theme_color'],
            "background_color": PWA_CONFIG['background_color'],
            "display": PWA_CONFIG['display'],
            "start_url": PWA_CONFIG['start_url'],
            "scope": PWA_CONFIG['scope'],
            "icons": PWA_CONFIG['icons']
        }
        
        return json.dumps(manifest, indent=2)
    
    @staticmethod
    def generate_service_worker() -> str:
        """Generate service worker for offline functionality"""
        service_worker = """
// Service Worker for Nigerian Road Risk Reporter
const CACHE_NAME = 'road-risk-reporter-v1';
const urlsToCache = [
  '/',
  '/static/css/main.css',
  '/static/js/main.js'
];

self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function(cache) {
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('fetch', function(event) {
  event.respondWith(
    caches.match(event.request)
      .then(function(response) {
        if (response) {
          return response;
        }
        return fetch(event.request);
      }
    )
  );
});

self.addEventListener('push', function(event) {
  const options = {
    body: event.data.text(),
    icon: '/static/icon-192x192.png',
    badge: '/static/badge-72x72.png',
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
        return service_worker
    
    @staticmethod
    def inject_pwa_meta_tags():
        """Inject PWA meta tags into Streamlit"""
        pwa_meta = f"""
        <meta name="theme-color" content="{PWA_CONFIG['theme_color']}">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="default">
        <meta name="apple-mobile-web-app-title" content="{PWA_CONFIG['short_name']}">
        <link rel="manifest" href="/manifest.json">
        <link rel="apple-touch-icon" href="/static/icon-192x192.png">
        """
        
        st.markdown(f"""
        <head>
            {pwa_meta}
        </head>
        """, unsafe_allow_html=True)

class DeploymentManager:
    """Deployment and configuration manager"""
    
    @staticmethod
    def create_requirements_file():
        """Create comprehensive requirements.txt"""
        requirements = """# Nigerian Road Risk Reporter - Requirements
# Core dependencies
streamlit==1.28.1
pandas==2.0.3
plotly==5.17.0

# Security and encryption
cryptography==41.0.7

# Data processing
numpy==1.24.3

# Optional: PDF generation (for analytics export)
# fpdf2==2.7.6

# Optional: PWA support
# streamlit-pwa==0.1.0

# Development and testing
pytest==7.4.3
black==23.11.0
flake8==6.1.0
"""
        return requirements
    
    @staticmethod
    def create_gitignore():
        """Create comprehensive .gitignore"""
        gitignore = """# Python
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

# Virtual environments
venv/
env/
ENV/

# Database files
*.db
*.sqlite
*.sqlite3

# Environment variables
.env
.env.local
.env.production

# Encryption keys
*.key
*.pem

# Logs
*.log
logs/

# Uploads
uploads/
temp/

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

# Temporary files
*.tmp
*.temp
"""
        return gitignore
    
    @staticmethod
    def create_deployment_instructions():
        """Generate deployment instructions"""
        instructions = """
# 🚀 Deployment Instructions for Nigerian Road Risk Reporter

## Prerequisites
- Python 3.8 or higher
- Git
- Streamlit Cloud account (free)

## Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/v8_road_status_nigeria.git
   cd v8_road_status_nigeria
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run locally**
   ```bash
   streamlit run streamlit_app_minimal.py
   ```

## Streamlit Cloud Deployment

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Initial deployment"
   git push origin main
   ```

2. **Deploy on Streamlit Cloud**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Sign in with GitHub
   - Click "New app"
   - Select your repository: `v8_road_status_nigeria`
   - Set main file path: `streamlit_app_minimal.py`
   - Click "Deploy"

3. **Configure environment variables** (if needed)
   - In Streamlit Cloud dashboard
   - Go to Settings > Secrets
   - Add any required environment variables

## Security Considerations

1. **Environment Variables**
   - Store sensitive data in `.env` file (local) or Streamlit secrets (cloud)
   - Never commit encryption keys to Git

2. **Database Security**
   - SQLite files are automatically excluded via `.gitignore`
   - Consider using external database for production

3. **Access Control**
   - Implement proper authentication
   - Use role-based access control
   - Monitor security logs

## Monitoring and Maintenance

1. **Logs**
   - Check Streamlit Cloud logs for errors
   - Monitor security logs in the app

2. **Updates**
   - Regularly update dependencies
   - Monitor for security vulnerabilities

3. **Backup**
   - Regularly backup database files
   - Export important data

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure all dependencies are in `requirements.txt`
   - Check Python version compatibility

2. **Database Errors**
   - Verify database file permissions
   - Check for file locks

3. **Deployment Failures**
   - Check Streamlit Cloud logs
   - Verify main file path
   - Ensure all files are committed to Git

### Support

- Check the [Streamlit documentation](https://docs.streamlit.io)
- Review [Streamlit Cloud troubleshooting](https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app)
- Open issues on GitHub repository

## Performance Optimization

1. **Database Optimization**
   - Use indexes for frequently queried columns
   - Regular database maintenance

2. **Caching**
   - Implement Streamlit caching for expensive operations
   - Cache database queries where appropriate

3. **File Management**
   - Clean up temporary files
   - Monitor upload directory size
"""
        return instructions

def display_deployment_interface():
    """Display deployment interface"""
    st.markdown("# 🚀 Deployment & PWA Configuration")
    
    # PWA Configuration
    with st.expander("📱 PWA Configuration", expanded=False):
        st.markdown("### Progressive Web App Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            PWA_CONFIG['app_name'] = st.text_input(
                "App Name",
                value=PWA_CONFIG['app_name'],
                key="pwa_app_name"
            )
            
            PWA_CONFIG['short_name'] = st.text_input(
                "Short Name",
                value=PWA_CONFIG['short_name'],
                key="pwa_short_name"
            )
            
            PWA_CONFIG['theme_color'] = st.color_picker(
                "Theme Color",
                value=PWA_CONFIG['theme_color'],
                key="pwa_theme_color"
            )
        
        with col2:
            PWA_CONFIG['description'] = st.text_area(
                "Description",
                value=PWA_CONFIG['description'],
                key="pwa_description"
            )
            
            PWA_CONFIG['display'] = st.selectbox(
                "Display Mode",
                ['standalone', 'fullscreen', 'minimal-ui', 'browser'],
                index=0,
                key="pwa_display"
            )
        
        # Generate PWA files
        if st.button("Generate PWA Files", key="generate_pwa"):
            manifest = PWAManager.generate_manifest()
            service_worker = PWAManager.generate_service_worker()
            
            st.success("✅ PWA files generated!")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### manifest.json")
                st.code(manifest, language="json")
            
            with col2:
                st.markdown("### service-worker.js")
                st.code(service_worker, language="javascript")
    
    # SMS Fallback Configuration
    with st.expander("📱 SMS Fallback System", expanded=False):
        st.markdown("### Communication Fallback")
        
        # Test SMS alerts
        test_report = {
            'id': 999,
            'risk_type': 'Robbery',
            'location': 'Lagos, Nigeria',
            'description': 'Test alert for deployment'
        }
        
        if st.button("Test SMS Alert", key="test_sms"):
            if SMSFallback.send_high_risk_alert(test_report):
                st.success("✅ SMS alert sent successfully!")
            else:
                st.error("❌ Failed to send SMS alert")
        
        # View alert logs
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT alert_type, message, sent_at, status
                FROM sms_alerts
                ORDER BY sent_at DESC
                LIMIT 10
            ''')
            
            alerts = cursor.fetchall()
            conn.close()
            
            if alerts:
                st.markdown("### Recent Alerts")
                for alert in alerts:
                    st.write(f"**{alert[0]}** - {alert[1]} - {alert[2]} - {alert[3]}")
            else:
                st.info("No SMS alerts found")
                
        except Exception as e:
            st.error(f"Error loading alerts: {str(e)}")
    
    # Deployment Configuration
    with st.expander("⚙️ Deployment Configuration", expanded=False):
        st.markdown("### Configuration Files")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Generate Requirements.txt", key="gen_requirements"):
                requirements = DeploymentManager.create_requirements_file()
                st.code(requirements, language="text")
        
        with col2:
            if st.button("Generate .gitignore", key="gen_gitignore"):
                gitignore = DeploymentManager.create_gitignore()
                st.code(gitignore, language="text")
        
        # Deployment instructions
        if st.button("Show Deployment Instructions", key="show_deploy"):
            instructions = DeploymentManager.create_deployment_instructions()
            st.markdown(instructions)
    
    # System Health Check
    with st.expander("🏥 System Health Check", expanded=False):
        st.markdown("### System Status")
        
        health_checks = []
        
        # Database check
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            conn.close()
            
            if tables:
                health_checks.append(("✅ Database", "Connected and tables exist"))
            else:
                health_checks.append(("❌ Database", "No tables found"))
        except Exception as e:
            health_checks.append(("❌ Database", f"Error: {str(e)}"))
        
        # File permissions check
        try:
            if os.access('.', os.W_OK):
                health_checks.append(("✅ File Permissions", "Write access available"))
            else:
                health_checks.append(("❌ File Permissions", "No write access"))
        except Exception as e:
            health_checks.append(("❌ File Permissions", f"Error: {str(e)}"))
        
        # Python version check
        python_version = sys.version_info
        if python_version.major >= 3 and python_version.minor >= 8:
            health_checks.append(("✅ Python Version", f"Python {python_version.major}.{python_version.minor}"))
        else:
            health_checks.append(("❌ Python Version", f"Python {python_version.major}.{python_version.minor} (3.8+ required)"))
        
        # Display health checks
        for check, status in health_checks:
            st.write(f"{check}: {status}")

def main():
    """Main function for Deployment Module"""
    st.set_page_config(
        page_title="Deployment & PWA",
        page_icon="🚀",
        layout="wide"
    )
    
    # Initialize PWA meta tags
    PWAManager.inject_pwa_meta_tags()
    
    # Display deployment interface
    display_deployment_interface()
    
    # Footer with deployment info
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🚀 Ready for deployment on Streamlit Cloud</p>
        <p>📱 PWA features enabled for mobile experience</p>
        <p>📱 SMS fallback system for critical alerts</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main() 