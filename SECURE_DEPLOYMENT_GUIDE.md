# 🔒 Secure Deployment Guide - Nigerian Road Risk Reporter

## 🚀 Overview

This guide provides step-by-step instructions for deploying the **SECURE VERSION** of the Nigerian Road Risk Reporter with all critical security vulnerabilities fixed.

## 📋 Pre-Deployment Checklist

### ✅ Security Fixes Implemented

- [x] **Secure Password Hashing**: bcrypt with salt
- [x] **SQL Injection Protection**: Parameterized queries
- [x] **Input Validation**: Comprehensive sanitization
- [x] **Rate Limiting**: Prevents abuse and brute force attacks
- [x] **Session Management**: Secure session handling
- [x] **File Upload Security**: MIME type and size validation
- [x] **Security Logging**: Comprehensive audit trails
- [x] **Account Lockout**: After failed login attempts
- [x] **XSS Protection**: Input sanitization
- [x] **Database Security**: Enhanced security tables

## 🛠️ Installation Steps

### 1. Install Dependencies

```bash
# Install critical security dependencies
pip install -r requirements.txt

# Verify bcrypt installation
python -c "import bcrypt; print('bcrypt installed successfully')"
```

### 2. Initialize Security Database

```bash
# Run the security initialization script
python security_fixes.py
```

### 3. Test Security Features

```bash
# Run comprehensive security tests
python security_test.py
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in your project root:

```bash
# Security Configuration
ENCRYPTION_KEY=your_very_long_random_secret_key_here
SECRET_KEY=another_very_long_random_secret_key_here

# Database Configuration
DATABASE_URL=sqlite:///users.db

# Session Configuration
SESSION_TIMEOUT_MINUTES=30
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_MINUTES=15

# File Upload Limits
MAX_FILE_SIZE_MB=5
ALLOWED_FILE_TYPES=.jpg,.jpeg,.png,.gif,.pdf

# Redis Configuration (Optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Security Logging
LOG_LEVEL=INFO
LOG_FILE=security.log
```

### Security Configuration

Update `security_fixes.py` configuration:

```python
SECURITY_CONFIG = {
    'session_timeout_minutes': 30,
    'max_login_attempts': 5,
    'lockout_duration_minutes': 30,
    'password_min_length': 12,
    'require_special_chars': True,
    'max_file_size_mb': 5,
    'allowed_file_types': {'.jpg', '.jpeg', '.png', '.gif', '.pdf'},
    'rate_limit_requests': 100,
    'rate_limit_window_minutes': 15,
    'enable_2fa': True,
    'enable_encryption': True
}
```

## 🚀 Deployment Options

### Option 1: Streamlit Cloud (Recommended)

1. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Add critical security fixes"
   git push origin main
   ```

2. **Deploy on Streamlit Cloud**:
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Connect your GitHub repository
   - Set main file: `streamlit_app_secure.py`
   - Add environment variables in Streamlit Cloud settings

3. **Environment Variables in Streamlit Cloud**:
   ```
   ENCRYPTION_KEY=your_encryption_key_here
   SECRET_KEY=your_secret_key_here
   ```

### Option 2: Local Development

```bash
# Run the secure version locally
streamlit run streamlit_app_secure.py

# Or run security tests
streamlit run security_test.py
```

### Option 3: Docker Deployment

Create `Dockerfile`:

```dockerfile
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
CMD ["streamlit", "run", "streamlit_app_secure.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

Build and run:

```bash
# Build Docker image
docker build -t road-risk-reporter-secure .

# Run container
docker run -p 8501:8501 \
  -e ENCRYPTION_KEY=your_key \
  -e SECRET_KEY=your_secret \
  road-risk-reporter-secure
```

## 🔒 Security Hardening

### 1. HTTPS Configuration

For production deployment, ensure HTTPS is enabled:

```python
# In your deployment configuration
st.set_page_config(
    page_title="Road Report Nigeria - Secure",
    page_icon="🛣️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add security headers
st.markdown("""
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
""", unsafe_allow_html=True)
```

### 2. Database Security

```python
# Use encrypted database connection
import sqlcipher3 as sqlite3

def get_secure_connection():
    conn = sqlite3.connect('users.db')
    conn.execute("PRAGMA key = 'your_encryption_key'")
    return conn
```

### 3. Rate Limiting Configuration

```python
# Configure rate limiting for different endpoints
@rate_limit_decorator(max_requests=10, window_seconds=300)  # 10 requests per 5 minutes
def login_endpoint():
    pass

@rate_limit_decorator(max_requests=5, window_seconds=600)   # 5 requests per 10 minutes
def registration_endpoint():
    pass
```

## 📊 Monitoring & Logging

### 1. Security Logs

Monitor `security.log` for suspicious activity:

```bash
# Monitor security logs in real-time
tail -f security.log

# Search for failed login attempts
grep "login_failed" security.log

# Search for suspicious activity
grep "suspicious_activity" security.log
```

### 2. Database Monitoring

```sql
-- Check failed login attempts
SELECT * FROM login_attempts WHERE success = FALSE ORDER BY attempt_time DESC LIMIT 10;

-- Check account lockouts
SELECT * FROM account_lockouts WHERE is_active = TRUE;

-- Check security audit logs
SELECT * FROM security_audit_logs ORDER BY created_at DESC LIMIT 10;
```

### 3. Performance Monitoring

```python
# Monitor rate limiting
def check_rate_limit_status():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM rate_limits WHERE window_end > datetime("now")')
    active_limits = cursor.fetchone()[0]
    conn.close()
    return active_limits
```

## 🚨 Security Alerts

### 1. Automated Alerts

Set up monitoring for:

- Multiple failed login attempts from same IP
- Unusual file upload patterns
- Rate limit violations
- Suspicious user activity
- Database access patterns

### 2. Alert Configuration

```python
def send_security_alert(alert_type: str, message: str):
    """Send security alerts"""
    # Configure your alert system (email, SMS, Slack, etc.)
    pass

def monitor_security_events():
    """Monitor and alert on security events"""
    # Check for suspicious patterns
    # Send alerts when thresholds are exceeded
    pass
```

## 🔄 Backup & Recovery

### 1. Database Backup

```bash
# Create automated backup script
#!/bin/bash
timestamp=$(date +%Y%m%d_%H%M%S)
backup_file="backup_${timestamp}.db"
cp users.db "backups/${backup_file}"
echo "Backup created: ${backup_file}"
```

### 2. Security Log Backup

```bash
# Backup security logs
cp security.log "logs/security_${timestamp}.log"
```

## 🧪 Testing

### 1. Security Testing

```bash
# Run comprehensive security tests
python security_test.py

# Test specific vulnerabilities
python -c "
from security_fixes import password_manager, input_validator
print('Testing password hashing...')
hashed = password_manager.hash_password('test123')
print('Testing input validation...')
sanitized = input_validator.sanitize_input('<script>alert(\"xss\")</script>')
print(f'Sanitized: {sanitized}')
"
```

### 2. Penetration Testing

Test for common vulnerabilities:

- SQL injection attempts
- XSS attacks
- CSRF attacks
- File upload vulnerabilities
- Authentication bypass attempts

## 📈 Performance Optimization

### 1. Database Optimization

```sql
-- Create indexes for security tables
CREATE INDEX idx_login_attempts_identifier ON login_attempts(identifier);
CREATE INDEX idx_security_logs_timestamp ON security_audit_logs(created_at);
CREATE INDEX idx_rate_limits_identifier ON rate_limits(identifier);
```

### 2. Caching

```python
# Implement caching for frequently accessed data
import functools
import time

@functools.lru_cache(maxsize=128)
def get_user_permissions(user_id: int):
    # Cache user permissions
    pass
```

## 🔐 Advanced Security Features

### 1. Two-Factor Authentication

```python
# Enable 2FA for admin users
if user_role == 'admin':
    # Require 2FA setup
    if not user_2fa_enabled:
        redirect_to_2fa_setup()
```

### 2. IP Whitelisting

```python
# Whitelist trusted IPs for admin access
TRUSTED_IPS = ['192.168.1.100', '10.0.0.50']

def check_ip_whitelist(ip_address: str) -> bool:
    return ip_address in TRUSTED_IPS
```

### 3. Session Security

```python
# Implement session rotation
def rotate_session(user_id: int):
    # Invalidate old sessions
    # Create new session
    pass
```

## 📞 Support & Maintenance

### 1. Regular Updates

- Update dependencies monthly
- Review security logs weekly
- Conduct security audits quarterly
- Update security configurations as needed

### 2. Incident Response

1. **Detect**: Monitor security logs
2. **Analyze**: Investigate suspicious activity
3. **Contain**: Block malicious IPs/users
4. **Eradicate**: Remove threats
5. **Recover**: Restore normal operations
6. **Learn**: Update security measures

### 3. Contact Information

- **Security Team**: security@yourdomain.com
- **Emergency Contact**: +234-XXX-XXX-XXXX
- **Bug Reports**: security-bugs@yourdomain.com

## ✅ Deployment Verification

After deployment, verify:

- [ ] Security tests pass
- [ ] HTTPS is enabled
- [ ] Rate limiting is active
- [ ] Security logging is working
- [ ] Database encryption is enabled
- [ ] File upload validation works
- [ ] Session management is secure
- [ ] Input validation is active

## 🎉 Success!

Your Nigerian Road Risk Reporter is now deployed with **critical security fixes** and is protected against:

- ✅ SQL injection attacks
- ✅ XSS attacks
- ✅ Brute force attacks
- ✅ Session hijacking
- ✅ File upload vulnerabilities
- ✅ Input validation bypass
- ✅ Rate limiting bypass

**Remember**: Security is an ongoing process. Regularly monitor, update, and test your security measures to maintain protection against evolving threats.

---

**Last Updated**: December 2024  
**Security Version**: 2.0  
**Compatibility**: Python 3.11+, Streamlit 1.28+ 