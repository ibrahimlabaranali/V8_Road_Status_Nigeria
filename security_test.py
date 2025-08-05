#!/usr/bin/env python3
"""
Security Testing Script for Nigerian Road Risk Reporter
Tests all critical security fixes and vulnerabilities
"""

import streamlit as st
import sqlite3
import time
import re
from datetime import datetime

# Import security fixes
try:
    from security_fixes import (
        password_manager, input_validator, rate_limiter, 
        session_manager, security_logger, two_factor_auth,
        get_client_ip, check_login_attempts, log_login_attempt,
        initialize_security_database, SECURITY_CONFIG
    )
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    st.error("⚠️ Security fixes module not available.")

def test_password_hashing():
    """Test secure password hashing"""
    st.subheader("🔐 Password Hashing Test")
    
    test_password = "TestPassword123!"
    
    if SECURITY_AVAILABLE:
        # Test bcrypt hashing
        hashed = password_manager.hash_password(test_password)
        st.write(f"**Original Password:** {test_password}")
        st.write(f"**Hashed Password:** {hashed[:50]}...")
        
        # Test verification
        is_valid = password_manager.verify_password(test_password, hashed)
        st.write(f"**Verification Result:** {'✅ Valid' if is_valid else '❌ Invalid'}")
        
        # Test wrong password
        is_valid_wrong = password_manager.verify_password("WrongPassword", hashed)
        st.write(f"**Wrong Password Test:** {'❌ Correctly rejected' if not is_valid_wrong else '⚠️ Security issue'}")
        
        if is_valid and not is_valid_wrong:
            st.success("✅ Password hashing test passed")
        else:
            st.error("❌ Password hashing test failed")
    else:
        st.warning("⚠️ Security module not available")

def test_password_strength():
    """Test password strength validation"""
    st.subheader("🔒 Password Strength Test")
    
    test_cases = [
        ("weak", "password"),
        ("short", "Abc123"),
        ("no_upper", "password123!"),
        ("no_lower", "PASSWORD123!"),
        ("no_number", "Password!"),
        ("no_special", "Password123"),
        ("strong", "StrongPassword123!"),
        ("common", "123456"),
        ("repeated", "aaaBBB123!"),
        ("keyboard", "qwerty123!")
    ]
    
    if SECURITY_AVAILABLE:
        for test_name, password in test_cases:
            is_strong, message = password_manager.validate_password_strength(password)
            status = "✅ Strong" if is_strong else "❌ Weak"
            st.write(f"**{test_name}:** {password} - {status}")
            if not is_strong:
                st.write(f"  *Reason:* {message}")
        
        st.success("✅ Password strength validation test completed")
    else:
        st.warning("⚠️ Security module not available")

def test_input_validation():
    """Test input validation and sanitization"""
    st.subheader("🛡️ Input Validation Test")
    
    test_cases = [
        ("normal", "Hello World"),
        ("xss_attempt", "<script>alert('xss')</script>"),
        ("sql_injection", "'; DROP TABLE users; --"),
        ("long_input", "A" * 300),
        ("empty", ""),
        ("special_chars", "!@#$%^&*()"),
        ("email_valid", "test@example.com"),
        ("email_invalid", "invalid-email"),
        ("phone_valid", "+2348012345678"),
        ("phone_invalid", "12345"),
        ("nin_valid", "12345678901"),
        ("nin_invalid", "123456789")
    ]
    
    if SECURITY_AVAILABLE:
        for test_name, input_text in test_cases:
            sanitized = input_validator.sanitize_input(input_text)
            st.write(f"**{test_name}:**")
            st.write(f"  Original: {input_text}")
            st.write(f"  Sanitized: {sanitized}")
            
            # Test specific validations
            if "email" in test_name:
                is_valid = input_validator.validate_email(input_text)
                st.write(f"  Email Valid: {'✅' if is_valid else '❌'}")
            
            if "phone" in test_name:
                is_valid = input_validator.validate_phone(input_text)
                st.write(f"  Phone Valid: {'✅' if is_valid else '❌'}")
            
            if "nin" in test_name:
                is_valid = input_validator.validate_nin(input_text)
                st.write(f"  NIN Valid: {'✅' if is_valid else '❌'}")
        
        st.success("✅ Input validation test completed")
    else:
        st.warning("⚠️ Security module not available")

def test_rate_limiting():
    """Test rate limiting functionality"""
    st.subheader("⏱️ Rate Limiting Test")
    
    if SECURITY_AVAILABLE:
        test_ip = "192.168.1.1"
        max_requests = 5
        window_seconds = 60
        
        st.write(f"**Test Configuration:**")
        st.write(f"  Max Requests: {max_requests}")
        st.write(f"  Window: {window_seconds} seconds")
        st.write(f"  Test IP: {test_ip}")
        
        # Test rate limiting
        results = []
        for i in range(max_requests + 2):
            is_allowed = rate_limiter.check_rate_limit(test_ip, max_requests, window_seconds)
            results.append(is_allowed)
            st.write(f"  Request {i+1}: {'✅ Allowed' if is_allowed else '❌ Blocked'}")
        
        # Check if rate limiting worked correctly
        expected = [True] * max_requests + [False] * 2
        if results == expected:
            st.success("✅ Rate limiting test passed")
        else:
            st.error("❌ Rate limiting test failed")
    else:
        st.warning("⚠️ Security module not available")

def test_session_management():
    """Test secure session management"""
    st.subheader("🔑 Session Management Test")
    
    if SECURITY_AVAILABLE:
        # Test user data
        test_user = {
            'id': 1,
            'full_name': 'Test User',
            'role': 'user',
            'login_time': datetime.now().isoformat()
        }
        
        # Create session
        session_id = session_manager.create_session(test_user)
        st.write(f"**Session Created:** {session_id[:20]}...")
        
        # Retrieve session
        session_data = session_manager.get_session(session_id)
        if session_data:
            st.write(f"**Session Retrieved:** ✅")
            st.write(f"  User: {session_data.get('full_name')}")
            st.write(f"  Role: {session_data.get('role')}")
        else:
            st.write("**Session Retrieved:** ❌")
        
        # Validate session
        is_valid = session_manager.validate_session(session_id)
        st.write(f"**Session Valid:** {'✅' if is_valid else '❌'}")
        
        # Test invalid session
        invalid_session = "invalid_session_id"
        is_valid_invalid = session_manager.validate_session(invalid_session)
        st.write(f"**Invalid Session Test:** {'✅ Correctly rejected' if not is_valid_invalid else '❌ Security issue'}")
        
        # Clean up
        session_manager.delete_session(session_id)
        
        if is_valid and not is_valid_invalid:
            st.success("✅ Session management test passed")
        else:
            st.error("❌ Session management test failed")
    else:
        st.warning("⚠️ Security module not available")

def test_sql_injection_protection():
    """Test SQL injection protection"""
    st.subheader("💉 SQL Injection Protection Test")
    
    malicious_inputs = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users VALUES (1, 'hacker', 'hacker@evil.com'); --",
        "admin'--",
        "1' UNION SELECT * FROM users--",
        "<script>alert('xss')</script>",
        "'; UPDATE users SET role='admin' WHERE id=1; --"
    ]
    
    st.write("**Testing malicious inputs:**")
    
    for i, malicious_input in enumerate(malicious_inputs, 1):
        # Test input sanitization
        if SECURITY_AVAILABLE:
            sanitized = input_validator.sanitize_input(malicious_input)
            st.write(f"  **Test {i}:**")
            st.write(f"    Original: {malicious_input}")
            st.write(f"    Sanitized: {sanitized}")
            
            # Check if dangerous characters were removed
            dangerous_chars = ["'", '"', ";", "<", ">"]
            has_dangerous = any(char in sanitized for char in dangerous_chars)
            st.write(f"    Safe: {'✅' if not has_dangerous else '❌'}")
        else:
            st.write(f"  **Test {i}:** {malicious_input}")
    
    st.success("✅ SQL injection protection test completed")

def test_database_security():
    """Test database security measures"""
    st.subheader("🗄️ Database Security Test")
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if security tables exist
        security_tables = [
            'security_audit_logs',
            'login_attempts', 
            'account_lockouts',
            'rate_limits',
            'two_factor_auth'
        ]
        
        st.write("**Security Tables Check:**")
        for table in security_tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            exists = cursor.fetchone() is not None
            st.write(f"  {table}: {'✅' if exists else '❌'}")
        
        # Check users table security columns
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        security_columns = [
            'two_factor_enabled',
            'account_locked',
            'failed_attempts',
            'last_login'
        ]
        
        st.write("**Users Table Security Columns:**")
        for column in security_columns:
            exists = column in columns
            st.write(f"  {column}: {'✅' if exists else '❌'}")
        
        conn.close()
        st.success("✅ Database security test completed")
        
    except Exception as e:
        st.error(f"❌ Database security test failed: {e}")

def test_security_logging():
    """Test security logging functionality"""
    st.subheader("📝 Security Logging Test")
    
    if SECURITY_AVAILABLE:
        # Test logging different events
        test_events = [
            ("test_login", "Test login attempt", "INFO"),
            ("test_failed_login", "Test failed login", "WARNING"),
            ("test_suspicious_activity", "Test suspicious activity", "ERROR")
        ]
        
        st.write("**Testing security event logging:**")
        for event_type, details, severity in test_events:
            security_logger.log_security_event(event_type, details, severity, user_id=999)
            st.write(f"  Logged: {event_type} - {severity}")
        
        # Check if log file exists
        import os
        if os.path.exists('security.log'):
            st.write("**Log File:** ✅ security.log exists")
            
            # Read last few lines
            with open('security.log', 'r') as f:
                lines = f.readlines()
                if lines:
                    st.write("**Recent Log Entries:**")
                    for line in lines[-3:]:  # Last 3 lines
                        st.write(f"  {line.strip()}")
        else:
            st.write("**Log File:** ❌ security.log not found")
        
        st.success("✅ Security logging test completed")
    else:
        st.warning("⚠️ Security module not available")

def run_security_audit():
    """Run comprehensive security audit"""
    st.title("🔒 Security Audit Report")
    st.markdown("Comprehensive security testing for Nigerian Road Risk Reporter")
    
    # Security status
    if SECURITY_AVAILABLE:
        st.success("✅ Security fixes module is available and active")
    else:
        st.error("❌ Security fixes module is not available")
        st.warning("⚠️ Running security tests in fallback mode")
    
    # Run all tests
    test_password_hashing()
    st.divider()
    
    test_password_strength()
    st.divider()
    
    test_input_validation()
    st.divider()
    
    test_rate_limiting()
    st.divider()
    
    test_session_management()
    st.divider()
    
    test_sql_injection_protection()
    st.divider()
    
    test_database_security()
    st.divider()
    
    test_security_logging()
    st.divider()
    
    # Security recommendations
    st.subheader("🔐 Security Recommendations")
    
    recommendations = [
        "✅ Use HTTPS in production",
        "✅ Implement proper CORS policies",
        "✅ Set up automated security monitoring",
        "✅ Regular security updates and patches",
        "✅ Implement backup and recovery procedures",
        "✅ Set up security alerting system",
        "✅ Conduct regular security audits",
        "✅ Train users on security best practices"
    ]
    
    for rec in recommendations:
        st.write(f"  {rec}")
    
    st.success("🎉 Security audit completed!")

def main():
    st.set_page_config(
        page_title="Security Audit",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Security Testing & Audit")
    st.markdown("Comprehensive security testing for the Nigerian Road Risk Reporter")
    
    # Run security audit
    run_security_audit()

if __name__ == "__main__":
    main() 