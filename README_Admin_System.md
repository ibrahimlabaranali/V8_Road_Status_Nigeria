# 🔐 Nigerian Road Risk Reporter - Modular Admin System

A lightweight, secure, and modular administrative control system designed for the Nigerian Road Risk Reporter App, fully deployable on Streamlit Cloud.

## 🚀 Features

### 🔐 Step 7 - Admin Login + Dashboard + Moderation Panel
- **Secure Admin Authentication**: Email/phone + password with 2FA simulation
- **Session State Management**: Persistent login across modules
- **Admin Dashboard**: Real-time statistics and report overview
- **Moderation Panel**: Verify, flag, and delete reports with audit logging
- **20km Radius Notifications**: Simulated proximity alerts

### 👥 Step 8 - User Management + Risk Config
- **User Management**: View, filter, and manage all users
- **Role Management**: Promote, demote, suspend, and re-verify users
- **Risk Type Configuration**: Add, edit, and manage risk categories
- **Advice Templates**: Customizable safety advice for each risk type
- **System Settings**: Configurable thresholds and retention policies

### 👍 Step 9 - Community Validation System
- **Upvote System**: Community-driven report validation
- **Duplicate Prevention**: One vote per user per report
- **Trust Scoring**: Automated trust calculation based on upvotes
- **GPS Validation Simulation**: Location-based validation framework

## 🛡️ Security Features

- **SHA256 Password Hashing**: Built-in Python hashing
- **Session State Management**: Secure session tracking
- **Role-Based Access Control**: Admin-only functionality
- **Comprehensive Audit Logging**: All actions tracked and logged
- **2FA Simulation**: Two-factor authentication framework
- **Input Validation**: Secure data handling

## 📁 Directory Structure

```
├── db_setup.py              # Shared database initialization
├── admin_main.py            # Main entry point
├── admin_login.py           # Admin authentication
├── admin_dashboard.py       # Dashboard and moderation
├── admin_config_panel.py    # User management and config
├── community_validation.py  # Community validation system
├── admin_logs.py           # Admin action logs
├── config.json             # Risk types and advice templates
├── db/                     # Database directory
│   ├── users.db           # User accounts and roles
│   ├── risk_reports.db    # Risk reports and status
│   ├── admin_logs.db      # Administrative audit trail
│   └── upvotes.db         # Community validation tracking
└── README_Admin_System.md  # This file
```

## 🗄️ Database Schema

### Users Database (`db/users.db`)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    phone_number TEXT NOT NULL UNIQUE,
    email TEXT,
    role TEXT NOT NULL,
    nin_or_passport TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Risk Reports Database (`db/risk_reports.db`)
```sql
CREATE TABLE risk_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    risk_type TEXT NOT NULL,
    description TEXT NOT NULL,
    location TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    voice_file_path TEXT,
    image_file_path TEXT,
    source_type TEXT DEFAULT 'user',
    source_url TEXT,
    status TEXT DEFAULT 'pending',
    confirmations INTEGER DEFAULT 0,
    upvotes INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Admin Logs Database (`db/admin_logs.db`)
```sql
CREATE TABLE admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL,
    admin_name TEXT NOT NULL,
    admin_email TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Upvotes Database (`db/upvotes.db`)
```sql
CREATE TABLE upvotes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    report_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, report_id)
);
```

## 🚀 Deployment Instructions

### 1. Streamlit Cloud Deployment

1. **Upload Files**: Upload all Python files and `config.json` to your Streamlit Cloud repository
2. **Set Main File**: Set `admin_main.py` as the main file in Streamlit Cloud settings
3. **Requirements**: Ensure `requirements.txt` contains only `streamlit==1.28.1`
4. **Deploy**: Deploy and access the admin system

### 2. Local Development

```bash
# Install dependencies
pip install streamlit==1.28.1

# Run the admin system
streamlit run admin_main.py

# Or run individual modules
streamlit run admin_login.py
streamlit run admin_dashboard.py
streamlit run admin_config_panel.py
streamlit run community_validation.py
streamlit run admin_logs.py
```

## 🔐 Demo Credentials

**Default Admin Account:**
- **Email:** admin@roadrisk.com
- **Phone:** +2348012345678
- **Password:** admin123
- **OTP:** 123456

*Note: The demo admin account is created automatically on first run.*

## 📊 Module Descriptions

### `admin_main.py`
- Main entry point for the admin system
- Redirects to login or dashboard based on session state
- Provides system overview and quick access

### `admin_login.py`
- Secure admin authentication with 2FA
- Session state management
- Demo admin account creation
- Login attempt logging

### `admin_dashboard.py`
- Real-time report statistics
- Report moderation panel
- Status updates and deletions
- Proximity alert simulation

### `admin_config_panel.py`
- User management interface
- Role assignment and user actions
- Risk type configuration
- Advice template management

### `community_validation.py`
- Community upvote system
- Trust score calculation
- GPS validation simulation
- Community statistics

### `admin_logs.py`
- Complete audit trail
- Action filtering and search
- CSV export functionality
- Log statistics and analysis

## 🔧 Configuration

### `config.json`
```json
{
  "risk_types": [
    {
      "name": "Robbery",
      "color": "#dc3545",
      "icon": "🚨",
      "description": "Armed robbery or theft incidents"
    }
  ],
  "advice_templates": {
    "Robbery": "🚨 **Robbery Alert**: Avoid this area, especially at night."
  },
  "system_settings": {
    "auto_verify_threshold": 3,
    "report_retention_days": 90,
    "log_retention_days": 180,
    "require_2fa": true
  }
}
```

## 🛡️ Security Best Practices

1. **Password Security**: Use strong passwords in production
2. **2FA Implementation**: Replace simulation with real 2FA
3. **Session Management**: Implement proper session timeouts
4. **Input Validation**: Validate all user inputs
5. **Audit Logging**: Monitor admin actions regularly
6. **Database Security**: Secure database access and backups

## 🔄 Session State Management

The system uses Streamlit's session state for:
- Admin authentication status (`admin_logged_in`)
- Admin user data (`admin_user`)
- Cross-module navigation
- Persistent login sessions

## 📈 Monitoring and Analytics

- **Admin Activity Tracking**: All actions logged with timestamps
- **User Management Analytics**: Role changes and user statistics
- **Report Moderation Metrics**: Verification and flagging statistics
- **Community Engagement**: Upvote patterns and trust scores

## 🚀 Future Enhancements

- **Real GPS Integration**: Replace simulation with actual GPS
- **Advanced Analytics**: Machine learning for report validation
- **Mobile App Integration**: Native mobile admin interface
- **API Development**: RESTful API for external integrations
- **Advanced Security**: OAuth, SSO, and real 2FA
- **Automated Moderation**: AI-powered content moderation

## 📞 Support

For technical support or questions about the admin system:
- Check the database logs for error details
- Verify all required files are present
- Ensure proper file permissions
- Test with demo credentials first

## 📄 License

This admin system is part of the Nigerian Road Risk Reporter project and follows the same licensing terms.

---

**Built with ❤️ for Nigerian road safety and community security.** 