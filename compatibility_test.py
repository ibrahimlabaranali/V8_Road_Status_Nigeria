#!/usr/bin/env python3
"""
Compatibility Test for Nigerian Road Risk Reporter
Tests all dependencies and basic functionality
"""

import sys
import importlib
import sqlite3
from datetime import datetime

def test_imports():
    """Test all required imports"""
    print("🔍 Testing imports...")
    
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
        'urllib.request',
        'urllib.parse'
    ]
    
    optional_modules = [
        'pandas',
        'plotly',
        'bcrypt',
        'pyotp',
        'numpy'
    ]
    
    failed_imports = []
    
    # Test required modules
    for module in required_modules:
        try:
            importlib.import_module(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module}: {e}")
            failed_imports.append(module)
    
    # Test optional modules
    print("\n🔍 Testing optional imports...")
    for module in optional_modules:
        try:
            importlib.import_module(module)
            print(f"✅ {module} (optional)")
        except ImportError:
            print(f"⚠️ {module} (optional) - not installed")
    
    return len(failed_imports) == 0

def test_database_creation():
    """Test database creation"""
    print("\n🗄️ Testing database creation...")
    
    try:
        # Test SQLite connection
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        # Test basic table creation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_table (
                id INTEGER PRIMARY KEY,
                name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Test insert
        cursor.execute('INSERT INTO test_table (name) VALUES (?)', ('test',))
        
        # Test select
        cursor.execute('SELECT * FROM test_table')
        result = cursor.fetchone()
        
        conn.close()
        
        if result and result[1] == 'test':
            print("✅ Database operations successful")
            return True
        else:
            print("❌ Database operations failed")
            return False
            
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_security_functions():
    """Test security functions"""
    print("\n🔒 Testing security functions...")
    
    try:
        import hashlib
        import secrets
        
        # Test password hashing
        password = "test_password_123"
        salt = secrets.token_hex(16)
        hash_obj = hashlib.sha256()
        hash_obj.update((password + salt).encode('utf-8'))
        hashed = f"{salt}${hash_obj.hexdigest()}"
        
        # Test password verification
        salt_from_hash, hash_value = hashed.split('$', 1)
        hash_obj = hashlib.sha256()
        hash_obj.update((password + salt_from_hash).encode('utf-8'))
        is_valid = hash_obj.hexdigest() == hash_value
        
        if is_valid:
            print("✅ Password hashing and verification successful")
            return True
        else:
            print("❌ Password verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        return False

def test_streamlit_import():
    """Test Streamlit import and basic functionality"""
    print("\n🌐 Testing Streamlit...")
    
    try:
        import streamlit as st
        
        # Test basic Streamlit functions
        if hasattr(st, 'set_page_config'):
            print("✅ Streamlit basic functions available")
            return True
        else:
            print("❌ Streamlit functions not available")
            return False
            
    except Exception as e:
        print(f"❌ Streamlit test failed: {e}")
        return False

def test_file_structure():
    """Test if required files exist"""
    print("\n📁 Testing file structure...")
    
    required_files = [
        'streamlit_app_minimal.py',
        'streamlit_app_secure.py', 
        'streamlit_app_cloud.py',
        'requirements.txt',
        'README.md'
    ]
    
    missing_files = []
    
    for file in required_files:
        try:
            with open(file, 'r') as f:
                print(f"✅ {file}")
        except FileNotFoundError:
            print(f"❌ {file} - not found")
            missing_files.append(file)
    
    return len(missing_files) == 0

def main():
    """Run all compatibility tests"""
    print("🚀 Nigerian Road Risk Reporter - Compatibility Test")
    print("=" * 50)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Imports", test_imports),
        ("Database", test_database_creation),
        ("Security", test_security_functions),
        ("Streamlit", test_streamlit_import)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Application is ready for deployment.")
        return True
    else:
        print("⚠️ Some tests failed. Please fix issues before deployment.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 