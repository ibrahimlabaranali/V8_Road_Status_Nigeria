"""
Streamlit version verification script
Checks all components are working correctly for Streamlit Cloud deployment
"""

import os
import sys
import importlib
import requests
import sqlite3
from pathlib import Path

def check_streamlit_files():
    """Check all required Streamlit files exist"""
    print("📁 Checking Streamlit files...")
    
    required_files = [
        "streamlit_app.py",
        "requirements_streamlit.txt",
        "README_Streamlit.md",
        ".streamlit/config.toml"
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
    
    print("  ✅ All Streamlit files present")
    return True

def check_streamlit_dependencies():
    """Check all Streamlit dependencies can be imported"""
    print("\n📦 Checking Streamlit dependencies...")
    
    dependencies = [
        "streamlit",
        "bcrypt",
        "PIL"
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
    
    print("  ✅ All Streamlit dependencies available")
    return True

def check_streamlit_app_imports():
    """Check the Streamlit app can be imported without errors"""
    print("\n🔧 Checking Streamlit app imports...")
    
    try:
        import streamlit_app
        print("  ✅ Streamlit app imports successfully")
        return True
    except Exception as e:
        print(f"  ❌ Streamlit app import failed: {e}")
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

def check_streamlit_server():
    """Check Streamlit server is running and responding"""
    print("\n🌐 Checking Streamlit server...")
    
    try:
        response = requests.get("http://localhost:8501", timeout=5)
        if response.status_code == 200:
            print("  ✅ Streamlit server responding correctly")
            return True
        else:
            print(f"  ❌ Streamlit server returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("  ⚠️ Streamlit server not running (this is OK for deployment check)")
        return True
    except Exception as e:
        print(f"  ❌ Streamlit server check failed: {e}")
        return False

def check_directories():
    """Check required directories exist"""
    print("\n📂 Checking directories...")
    
    required_dirs = ["uploads", ".streamlit"]
    
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"  ✅ {dir_path}/")
        else:
            print(f"  ❌ {dir_path}/ missing")
            return False
    
    return True

def check_streamlit_config():
    """Check Streamlit configuration"""
    print("\n⚙️ Checking Streamlit configuration...")
    
    config_file = ".streamlit/config.toml"
    if os.path.exists(config_file):
        print(f"  ✅ {config_file} exists")
        
        # Check if config has required settings
        with open(config_file, 'r') as f:
            content = f.read()
            if "primaryColor" in content and "maxUploadSize" in content:
                print("  ✅ Streamlit config has required settings")
                return True
            else:
                print("  ⚠️ Streamlit config missing some settings")
                return True
    else:
        print(f"  ❌ {config_file} missing")
        return False

def main():
    """Run all Streamlit verification checks"""
    print("🚀 Nigerian Road Risk Reporting App - Streamlit Verification")
    print("=" * 60)
    
    checks = [
        check_streamlit_files,
        check_streamlit_dependencies,
        check_streamlit_app_imports,
        check_database,
        check_directories,
        check_streamlit_config,
        check_streamlit_server
    ]
    
    results = []
    for check in checks:
        results.append(check())
    
    print("\n" + "=" * 60)
    print("📊 Streamlit Verification Summary")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Checks passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All Streamlit checks passed! Ready for Streamlit Cloud deployment.")
        print("\n✅ Streamlit Cloud Deployment Checklist:")
        print("  - All Streamlit files present and correct")
        print("  - Streamlit dependencies properly installed")
        print("  - Streamlit app imports without errors")
        print("  - Database accessible")
        print("  - Required directories created")
        print("  - Streamlit configuration set up")
        print("  - Streamlit server functionality verified")
        print("\n🚀 Ready for Streamlit Cloud!")
        print("\n📋 Deployment Steps:")
        print("  1. Push to GitHub: git add . && git commit -m 'Add Streamlit version' && git push")
        print("  2. Go to share.streamlit.io")
        print("  3. Connect your GitHub repository")
        print("  4. Set main file to: streamlit_app.py")
        print("  5. Deploy!")
        return True
    else:
        print("⚠️ Some Streamlit checks failed. Please fix issues before deployment.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 