#!/usr/bin/env python3
"""
Test script for Road Report Nigeria app
Run this to verify all functionality before deployment
"""

import sqlite3
import os
import sys

def test_database_connection():
    """Test database connection and table creation"""
    print("🔍 Testing database connection...")
    
    try:
        # Test database creation
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        required_tables = [
            'users', 'risk_reports', 'admin_logs', 'report_upvotes',
            'security_audit_logs', 'password_resets', 'login_attempts', 'account_lockouts'
        ]
        
        existing_tables = [table[0] for table in tables]
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            print(f"❌ Missing tables: {missing_tables}")
            return False
        
        print(f"✅ Database tables verified: {len(existing_tables)} tables found")
        
        # Test basic operations
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"✅ Users table accessible: {user_count} users found")
        
        cursor.execute("SELECT COUNT(*) FROM risk_reports")
        report_count = cursor.fetchone()[0]
        print(f"✅ Risk reports table accessible: {report_count} reports found")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_imports():
    """Test if all required modules can be imported"""
    print("🔍 Testing module imports...")
    
    required_modules = [
        'streamlit',
        'sqlite3',
        'hashlib',
        're',
        'json',
        'os',
        'time',
        'secrets',
        'datetime',
        'base64',
        'io',
        'typing',
        'urllib.request',
        'urllib.parse'
    ]
    
    failed_imports = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module} imported successfully")
        except ImportError as e:
            print(f"❌ {module} import failed: {e}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"❌ Failed imports: {failed_imports}")
        return False
    
    return True

def test_file_structure():
    """Test if all required files exist"""
    print("🔍 Testing file structure...")
    
    required_files = [
        'streamlit_app_minimal.py',
        'requirements.txt',
        'README.md',
        'nigerian_roads_data.py'
    ]
    
    missing_files = []
    
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file} found")
        else:
            print(f"❌ {file} missing")
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    
    return True

def test_app_syntax():
    """Test if the main app file has valid Python syntax"""
    print("🔍 Testing app syntax...")
    
    try:
        with open('streamlit_app_minimal.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try to compile the code
        compile(content, 'streamlit_app_minimal.py', 'exec')
        print("✅ App syntax is valid")
        return True
        
    except SyntaxError as e:
        print(f"❌ Syntax error in app: {e}")
        return False
    except Exception as e:
        print(f"❌ Error reading app file: {e}")
        return False

def test_requirements():
    """Test if requirements.txt is properly formatted"""
    print("🔍 Testing requirements.txt...")
    
    try:
        with open('requirements.txt', 'r') as f:
            requirements = f.readlines()
        
        if not requirements:
            print("❌ requirements.txt is empty")
            return False
        
        print(f"✅ requirements.txt contains {len(requirements)} packages")
        
        # Check for critical packages
        critical_packages = ['streamlit']
        for package in critical_packages:
            if any(package in req for req in requirements):
                print(f"✅ {package} found in requirements")
            else:
                print(f"❌ {package} missing from requirements")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error reading requirements.txt: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Road Report Nigeria - Pre-deployment Tests")
    print("=" * 50)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Module Imports", test_imports),
        ("App Syntax", test_app_syntax),
        ("Requirements", test_requirements),
        ("Database", test_database_connection)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name} Test:")
        if test_func():
            passed += 1
        else:
            print(f"❌ {test_name} test failed")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your app is ready for deployment!")
        print("\n🚀 Next steps:")
        print("1. Commit your changes to Git")
        print("2. Push to GitHub")
        print("3. Deploy to Streamlit Cloud")
        print("4. Test the live deployment")
    else:
        print("❌ Some tests failed. Please fix the issues before deploying.")
        print("\n🔧 Common fixes:")
        print("- Check for syntax errors in your code")
        print("- Ensure all required files exist")
        print("- Verify database setup")
        print("- Check import statements")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
