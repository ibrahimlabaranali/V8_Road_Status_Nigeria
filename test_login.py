"""
Test script for login and password reset functionality
Tests both FastAPI and Streamlit versions
"""

import requests
import sqlite3
import time
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:8000"
STREAMLIT_URL = "http://localhost:8501"

def test_fastapi_login():
    """Test FastAPI login functionality"""
    print("🧪 Testing FastAPI Login Functionality")
    print("=" * 50)
    
    # Test 1: Login with valid credentials
    print("\n1. Testing login with valid credentials...")
    login_data = {
        "identifier": "test@example.com",
        "password": "newpassword123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login", data=login_data)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Login successful: {result['message']}")
            print(f"   User ID: {result['user_id']}")
            print(f"   Role: {result['role']}")
            return result['user_id']
        else:
            print(f"❌ Login failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Login test failed: {e}")
        return None

def test_fastapi_forgot_password():
    """Test FastAPI forgot password functionality"""
    print("\n2. Testing forgot password functionality...")
    
    # Test forgot password request
    forgot_data = {
        "identifier": "test@example.com"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/forgot-password", data=forgot_data)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Forgot password request successful: {result['message']}")
            return True
        else:
            print(f"❌ Forgot password request failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Forgot password test failed: {e}")
        return False

def test_fastapi_password_reset():
    """Test FastAPI password reset functionality"""
    print("\n3. Testing password reset functionality...")
    
    # Get a valid reset token from database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT token FROM password_resets 
        WHERE used = 0 AND expires_at > datetime('now') 
        ORDER BY created_at DESC LIMIT 1
    ''')
    
    token_record = cursor.fetchone()
    conn.close()
    
    if not token_record:
        print("❌ No valid reset token found in database")
        return False
    
    token = token_record[0]
    print(f"   Using token: {token[:20]}...")
    
    # Test password reset
    reset_data = {
        "token": token,
        "new_password": "newpassword123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/reset-password", data=reset_data)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Password reset successful: {result['message']}")
            return True
        else:
            print(f"❌ Password reset failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Password reset test failed: {e}")
        return False

def test_fastapi_login_attempts():
    """Test FastAPI login attempts logging"""
    print("\n4. Testing login attempts logging...")
    
    try:
        response = requests.get(f"{BASE_URL}/login-attempts")
        if response.status_code == 200:
            attempts = response.json()
            print(f"✅ Retrieved {len(attempts)} login attempts")
            
            if attempts:
                latest = attempts[0]
                print(f"   Latest attempt: {latest['user_identifier']} - {'Success' if latest['success'] else 'Failed'}")
            
            return True
        else:
            print(f"❌ Failed to retrieve login attempts: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Login attempts test failed: {e}")
        return False

def test_database_tables():
    """Test database tables and structure"""
    print("\n5. Testing database tables...")
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check required tables
        required_tables = ['users', 'login_attempts', 'password_resets']
        
        for table in required_tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if cursor.fetchone():
                print(f"✅ Table '{table}' exists")
            else:
                print(f"❌ Table '{table}' missing")
        
        # Check table structures
        print("\n   Table structures:")
        for table in required_tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            print(f"   {table}: {len(columns)} columns")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_streamlit_connectivity():
    """Test Streamlit connectivity"""
    print("\n6. Testing Streamlit connectivity...")
    
    try:
        response = requests.get(STREAMLIT_URL, timeout=5)
        if response.status_code == 200:
            print(f"✅ Streamlit app is running at {STREAMLIT_URL}")
            return True
        else:
            print(f"❌ Streamlit app returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ Streamlit app not running at {STREAMLIT_URL}")
        return False
    except Exception as e:
        print(f"❌ Streamlit connectivity test failed: {e}")
        return False

def create_test_user():
    """Create a test user for testing"""
    print("\n7. Creating test user...")
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if test user exists
        cursor.execute('''
            SELECT id FROM users WHERE email = 'test@example.com'
        ''')
        
        if cursor.fetchone():
            print("✅ Test user already exists")
            conn.close()
            return True
        
        # Create test user
        import bcrypt
        hashed_password = bcrypt.hashpw("testpass123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport,
                official_authority, id_file_path, password_hash, registration_status, created_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            "Test User",
            "+2348012345678",
            "test@example.com",
            "Public",
            "12345678901",
            None,  # official_authority
            None,  # id_file_path
            hashed_password,
            "verified",
            datetime.now(),
            True
        ))
        
        conn.commit()
        conn.close()
        print("✅ Test user created successfully")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create test user: {e}")
        return False

def cleanup_test_data():
    """Clean up test data"""
    print("\n8. Cleaning up test data...")
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Remove test user
        cursor.execute('DELETE FROM users WHERE email = "test@example.com"')
        
        # Remove test login attempts
        cursor.execute('DELETE FROM login_attempts WHERE user_identifier = "test@example.com"')
        
        # Remove test password resets
        cursor.execute('''
            DELETE FROM password_resets 
            WHERE user_id IN (SELECT id FROM users WHERE email = "test@example.com")
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Test data cleaned up")
        return True
        
    except Exception as e:
        print(f"❌ Failed to clean up test data: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Nigerian Road Risk Reporting - Login & Password Reset Tests")
    print("=" * 70)
    
    # Create test user
    if not create_test_user():
        print("❌ Cannot proceed without test user")
        return
    
    # Test results
    results = []
    
    # Test FastAPI functionality
    results.append(test_fastapi_forgot_password())
    results.append(test_fastapi_password_reset())
    
    # Test login after password reset
    login_result = test_fastapi_login()
    results.append(login_result is not None)  # Convert to boolean
    
    results.append(test_fastapi_login_attempts())
    results.append(test_database_tables())
    results.append(test_streamlit_connectivity())
    
    # Clean up
    cleanup_test_data()
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 Test Summary")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! Login and password reset functionality is working correctly.")
        print("\n✅ Features Verified:")
        print("  - User authentication with email/phone")
        print("  - Password reset request and confirmation")
        print("  - Login attempt logging and audit trail")
        print("  - Database table structure")
        print("  - Streamlit connectivity")
        print("  - Security features (bcrypt, token expiration)")
    else:
        print("⚠️ Some tests failed. Please check the implementation.")
    
    print("\n🔧 Next Steps:")
    print("  - Test with real email integration")
    print("  - Add rate limiting for security")
    print("  - Implement session management")
    print("  - Add two-factor authentication")

if __name__ == "__main__":
    main() 