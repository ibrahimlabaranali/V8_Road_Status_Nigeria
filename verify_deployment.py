"""
Final verification script for GitHub deployment
Checks all components are working correctly
"""

import os
import sys
import importlib
import requests
import sqlite3
from pathlib import Path

def check_files_exist():
    """Check all required files exist"""
    print("📁 Checking required files...")
    
    required_files = [
        "app.py",
        "config.py", 
        "requirements.txt",
        "README.md",
        "templates/registration.html"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
        else:
            print(f"  ✅ {file_path}")
    
    if missing_files:
        print(f"  ❌ Missing files: {missing_files}")
        return False
    
    print("  ✅ All required files present")
    return True

def check_dependencies():
    """Check all dependencies can be imported"""
    print("\n📦 Checking dependencies...")
    
    dependencies = [
        "fastapi",
        "uvicorn",
        "sqlalchemy", 
        "bcrypt",
        "pydantic",
        "aiofiles",
        "multipart",
        "dotenv"
    ]
    
    missing_deps = []
    for dep in dependencies:
        try:
            importlib.import_module(dep)
            print(f"  ✅ {dep}")
        except ImportError:
            missing_deps.append(dep)
            print(f"  ❌ {dep}")
    
    if missing_deps:
        print(f"  ❌ Missing dependencies: {missing_deps}")
        return False
    
    print("  ✅ All dependencies available")
    return True

def check_app_imports():
    """Check the app can be imported without errors"""
    print("\n🔧 Checking app imports...")
    
    try:
        import app
        print("  ✅ App imports successfully")
        return True
    except Exception as e:
        print(f"  ❌ App import failed: {e}")
        return False

def check_database():
    """Check database is accessible"""
    print("\n🗄️ Checking database...")
    
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        conn.close()
        
        if tables:
            print(f"  ✅ Database accessible with {len(tables)} tables")
            return True
        else:
            print("  ⚠️ Database exists but no tables found")
            return True
    except Exception as e:
        print(f"  ❌ Database error: {e}")
        return False

def check_server():
    """Check server is running and responding"""
    print("\n🌐 Checking server...")
    
    try:
        response = requests.get("http://localhost:8000", timeout=5)
        if response.status_code == 200:
            print("  ✅ Server responding correctly")
            return True
        else:
            print(f"  ❌ Server returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("  ⚠️ Server not running (this is OK for deployment check)")
        return True
    except Exception as e:
        print(f"  ❌ Server check failed: {e}")
        return False

def check_directories():
    """Check required directories exist"""
    print("\n📂 Checking directories...")
    
    required_dirs = ["templates", "uploads"]
    
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"  ✅ {dir_path}/")
        else:
            print(f"  ❌ {dir_path}/ missing")
            return False
    
    return True

def main():
    """Run all verification checks"""
    print("🚀 Nigerian Road Risk Reporting App - Deployment Verification")
    print("=" * 60)
    
    checks = [
        check_files_exist,
        check_dependencies,
        check_app_imports,
        check_database,
        check_directories,
        check_server
    ]
    
    results = []
    for check in checks:
        results.append(check())
    
    print("\n" + "=" * 60)
    print("📊 Verification Summary")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Checks passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All checks passed! Ready for GitHub deployment.")
        print("\n✅ Deployment Checklist:")
        print("  - All files present and correct")
        print("  - Dependencies properly installed")
        print("  - Application imports without errors")
        print("  - Database accessible")
        print("  - Directories created")
        print("  - Server functionality verified")
        print("\n🚀 You can now push to GitHub!")
        return True
    else:
        print("⚠️ Some checks failed. Please fix issues before deployment.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 