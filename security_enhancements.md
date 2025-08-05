# 🔒 Security Enhancements for Nigerian Road Risk Reporter

## 🚀 Implemented Security Features

### 1. Enhanced Login Attempt Management
- **5 Attempts Limit**: Users get 5 login attempts before account lockout
- **30-Minute Lockout**: Accounts are locked for 30 minutes after 5 failed attempts
- **Database Tracking**: All login attempts are logged to database with IP tracking
- **Session State Management**: Proper session state handling for attempt counting

### 2. Database Security Tables
- **Security Audit Logs**: Track all security-related activities
- **Login Attempts**: Detailed logging of all login attempts
- **Account Lockouts**: Persistent lockout management
- **Rate Limiting**: Request rate limiting capabilities

### 3. Enhanced Authentication
- **IP Tracking**: Basic IP address tracking for security monitoring
- **Audit Logging**: All successful and failed logins are logged
- **Session Management**: Proper session timeout and cleanup

## 🛡️ Additional Security Recommendations

### 1. Production Environment Security

#### A. Web Application Firewall (WAF)
```python
# Recommended WAF Configuration
WAF_CONFIG = {
    'enable_rate_limiting': True,
    'max_requests_per_minute': 60,
    'block_suspicious_ips': True,
    'enable_ddos_protection': True,
    'sql_injection_protection': True,
    'xss_protection': True
}
```

#### B. HTTPS Implementation
- **SSL/TLS Certificate**: Use Let's Encrypt or commercial certificates
- **HSTS Headers**: Implement HTTP Strict Transport Security
- **Secure Cookies**: Set secure and httpOnly flags for session cookies

#### C. Environment Variables
```bash
# .env file (never commit to git)
DATABASE_URL=your_secure_database_url
SECRET_KEY=your_very_long_random_secret_key
ADMIN_EMAIL=admin@yourdomain.com
SMTP_PASSWORD=your_smtp_password
API_KEYS=your_external_api_keys
```

### 2. Database Security

#### A. Database Encryption
```python
# SQLite with encryption (using sqlcipher)
import sqlcipher3 as sqlite3

def get_secure_connection():
    conn = sqlite3.connect('users.db')
    conn.execute("PRAGMA key = 'your_encryption_key'")
    return conn
```

#### B. Input Validation and Sanitization
```python
def sanitize_input(input_string: str) -> str:
    """Sanitize user input to prevent SQL injection"""
    import re
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;\'\"\\]', '', input_string)
    return sanitized.strip()

def validate_and_sanitize_user_input(user_data: dict) -> dict:
    """Validate and sanitize all user inputs"""
    sanitized_data = {}
    for key, value in user_data.items():
        if isinstance(value, str):
            sanitized_data[key] = sanitize_input(value)
        else:
            sanitized_data[key] = value
    return sanitized_data
```

### 3. Advanced Security Features

#### A. Two-Factor Authentication (2FA)
```python
import pyotp
import qrcode

def generate_2fa_secret():
    """Generate 2FA secret for user"""
    return pyotp.random_base32()

def create_2fa_qr_code(secret: str, user_email: str):
    """Create QR code for 2FA setup"""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(user_email, issuer_name="Road Risk Reporter")
    return qrcode.make(provisioning_uri)

def verify_2fa_code(secret: str, code: str) -> bool:
    """Verify 2FA code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
```

#### B. Password Policy Enforcement
```python
def enhanced_password_validation(password: str) -> tuple[bool, str]:
    """Enhanced password validation with multiple checks"""
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Check for common passwords
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if password.lower() in common_passwords:
        errors.append("Password cannot be a common password")
    
    # Check for sequential characters
    if re.search(r'(.)\1{2,}', password):
        errors.append("Password cannot contain repeated characters")
    
    return len(errors) == 0, '; '.join(errors) if errors else "Password is strong"
```

#### C. Account Recovery System
```python
import secrets
import smtplib
from email.mime.text import MIMEText

def generate_recovery_token() -> str:
    """Generate secure recovery token"""
    return secrets.token_urlsafe(32)

def send_recovery_email(email: str, token: str):
    """Send password recovery email"""
    recovery_url = f"https://yourapp.com/reset-password?token={token}"
    
    message = f"""
    Hello,
    
    You requested a password reset for your Road Risk Reporter account.
    
    Click the following link to reset your password:
    {recovery_url}
    
    This link will expire in 1 hour.
    
    If you didn't request this, please ignore this email.
    
    Best regards,
    Road Risk Reporter Team
    """
    
    # Send email using your SMTP configuration
    # Implementation depends on your email service
```

### 4. Monitoring and Alerting

#### A. Security Monitoring
```python
def log_security_event(event_type: str, details: str, severity: str = "INFO"):
    """Log security events for monitoring"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'event_type': event_type,
        'details': details,
        'severity': severity,
        'ip_address': get_client_ip(),
        'user_agent': "Streamlit App"
    }
    
    # Log to database
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_audit_logs (user_ip, action, details, success)
            VALUES (?, ?, ?, ?)
        ''', (log_entry['ip_address'], event_type, details, True))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log security event: {e}")

def detect_suspicious_activity(user_id: int, action: str) -> bool:
    """Detect suspicious user activity"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check for rapid successive actions
        cursor.execute('''
            SELECT COUNT(*) FROM security_audit_logs 
            WHERE user_id = ? AND action = ? 
            AND created_at > datetime('now', '-5 minutes')
        ''', (user_id, action))
        
        recent_actions = cursor.fetchone()[0]
        conn.close()
        
        # Flag if more than 10 actions in 5 minutes
        if recent_actions > 10:
            log_security_event("suspicious_activity", 
                             f"User {user_id} performed {recent_actions} {action} actions in 5 minutes", 
                             "WARNING")
            return True
        
        return False
        
    except Exception:
        return False
```

#### B. Automated Alerts
```python
def send_security_alert(alert_type: str, message: str):
    """Send security alerts to administrators"""
    # Implementation for email/SMS alerts
    # This would integrate with your notification system
    pass

def monitor_failed_logins():
    """Monitor and alert on failed login patterns"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check for multiple failed logins from same IP
        cursor.execute('''
            SELECT user_ip, COUNT(*) FROM login_attempts 
            WHERE success = FALSE AND attempt_time > datetime('now', '-1 hour')
            GROUP BY user_ip HAVING COUNT(*) > 20
        ''')
        
        suspicious_ips = cursor.fetchall()
        
        for ip, count in suspicious_ips:
            send_security_alert("failed_login_attack", 
                              f"IP {ip} has {count} failed login attempts in the last hour")
        
        conn.close()
        
    except Exception as e:
        print(f"Failed to monitor failed logins: {e}")
```

### 5. Data Protection

#### A. Data Encryption
```python
from cryptography.fernet import Fernet
import base64

def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive user data"""
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())
    return base64.b64encode(encrypted_data).decode()

def decrypt_sensitive_data(encrypted_data: str, key: bytes) -> str:
    """Decrypt sensitive user data"""
    cipher = Fernet(key)
    decoded_data = base64.b64decode(encrypted_data.encode())
    decrypted_data = cipher.decrypt(decoded_data)
    return decrypted_data.decode()
```

#### B. Data Anonymization
```python
def anonymize_user_data(user_data: dict) -> dict:
    """Anonymize user data for analytics"""
    anonymized = user_data.copy()
    
    # Anonymize sensitive fields
    if 'email' in anonymized:
        anonymized['email'] = anonymized['email'][:3] + '***@***.com'
    
    if 'phone' in anonymized:
        anonymized['phone'] = anonymized['phone'][:4] + '****'
    
    if 'full_name' in anonymized:
        anonymized['full_name'] = anonymized['full_name'][0] + '***'
    
    return anonymized
```

### 6. API Security

#### A. API Rate Limiting
```python
from functools import wraps
import time

def rate_limit(max_requests: int, window_seconds: int):
    """Rate limiting decorator for API endpoints"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_ip = get_client_ip()
            current_time = time.time()
            
            # Check rate limit
            if not check_rate_limit(user_ip, max_requests, window_seconds, current_time):
                return {"error": "Rate limit exceeded"}, 429
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def check_rate_limit(user_ip: str, max_requests: int, window_seconds: int, current_time: float) -> bool:
    """Check if user has exceeded rate limit"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Clean old entries
        cursor.execute('''
            DELETE FROM rate_limits 
            WHERE window_end < datetime('now', '-{} seconds')
        '''.format(window_seconds))
        
        # Check current requests
        cursor.execute('''
            SELECT request_count FROM rate_limits 
            WHERE identifier = ? AND window_end > datetime('now', '-{} seconds')
        '''.format(window_seconds), (user_ip,))
        
        result = cursor.fetchone()
        
        if result and result[0] >= max_requests:
            conn.close()
            return False
        
        # Update or insert rate limit record
        if result:
            cursor.execute('''
                UPDATE rate_limits SET request_count = request_count + 1 
                WHERE identifier = ?
            ''', (user_ip,))
        else:
            window_end = datetime.now() + timedelta(seconds=window_seconds)
            cursor.execute('''
                INSERT INTO rate_limits (identifier, user_ip, request_count, window_end)
                VALUES (?, ?, 1, ?)
            ''', (user_ip, user_ip, window_end.isoformat()))
        
        conn.commit()
        conn.close()
        return True
        
    except Exception:
        return True  # Allow if rate limiting fails
```

### 7. Deployment Security

#### A. Docker Security
```dockerfile
# Use non-root user
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run application
CMD ["streamlit", "run", "streamlit_app_minimal.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

#### B. Environment Security
```bash
# Production environment variables
export STREAMLIT_SERVER_PORT=8501
export STREAMLIT_SERVER_ADDRESS=0.0.0.0
export STREAMLIT_SERVER_HEADLESS=true
export STREAMLIT_SERVER_ENABLE_CORS=false
export STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true
export STREAMLIT_SERVER_ENABLE_STATIC_SERVING=true
export STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
```

### 8. Backup and Recovery

#### A. Automated Backups
```python
import shutil
import schedule
import time
from datetime import datetime

def backup_database():
    """Create automated database backup"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f'backups/users_backup_{timestamp}.db'
    
    try:
        shutil.copy2('users.db', backup_path)
        log_security_event("backup_created", f"Database backup created: {backup_path}")
        
        # Keep only last 7 backups
        cleanup_old_backups()
        
    except Exception as e:
        log_security_event("backup_failed", f"Database backup failed: {str(e)}", "ERROR")

def cleanup_old_backups():
    """Remove backups older than 7 days"""
    import os
    import glob
    
    backup_files = glob.glob('backups/users_backup_*.db')
    current_time = time.time()
    
    for backup_file in backup_files:
        if os.path.getmtime(backup_file) < current_time - (7 * 24 * 3600):
            os.remove(backup_file)

# Schedule daily backups
schedule.every().day.at("02:00").do(backup_database)
```

## 🚨 Security Checklist

### Immediate Actions (High Priority)
- [x] Implement 5-attempt login limit with 30-minute lockout
- [x] Add database logging for all security events
- [x] Enhance password validation
- [x] Add IP tracking for login attempts
- [x] Implement session timeout management

### Short-term Actions (Medium Priority)
- [ ] Set up HTTPS/SSL certificates
- [ ] Implement rate limiting for API endpoints
- [ ] Add input validation and sanitization
- [ ] Set up automated security monitoring
- [ ] Implement backup and recovery procedures

### Long-term Actions (Low Priority)
- [ ] Implement Two-Factor Authentication (2FA)
- [ ] Add advanced threat detection
- [ ] Set up security alerting system
- [ ] Implement data encryption at rest
- [ ] Add comprehensive audit logging

## 📞 Security Contact Information

For security issues or vulnerabilities, please contact:
- **Security Team**: security@yourdomain.com
- **Emergency Contact**: +234-XXX-XXX-XXXX
- **Bug Bounty Program**: Available for critical vulnerabilities

---

**Note**: This security guide should be regularly updated as new threats emerge and security best practices evolve. 