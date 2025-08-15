#!/usr/bin/env python3
"""
Test script for Road Report Nigeria - Render App
Run this to verify the render app works locally before deployment
"""

import os
import sys
import subprocess

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

def test_render_app_syntax():
    """Test if the render app file has valid Python syntax"""
    print("🔍 Testing render app syntax...")
    
    try:
        with open('render_app.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try to compile the code
        compile(content, 'render_app.py', 'exec')
        print("✅ Render app syntax is valid")
        return True
        
    except SyntaxError as e:
        print(f"❌ Syntax error in render app: {e}")
        return False
    except Exception as e:
        print(f"❌ Error reading render app file: {e}")
        return False

def test_requirements():
    """Test if requirements_render.txt is properly formatted"""
    print("🔍 Testing requirements_render.txt...")
    
    try:
        with open('requirements_render.txt', 'r') as f:
            requirements = f.readlines()
        
        if not requirements:
            print("❌ requirements_render.txt is empty")
            return False
        
        print(f"✅ requirements_render.txt contains {len(requirements)} packages")
        
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
        print(f"❌ Error reading requirements_render.txt: {e}")
        return False

def test_runtime_txt():
    """Test if runtime.txt exists and has correct Python version"""
    print("🔍 Testing runtime.txt...")
    
    try:
        with open('runtime.txt', 'r') as f:
            runtime = f.read().strip()
        
        if runtime == 'python-3.10.13':
            print("✅ runtime.txt contains correct Python version: python-3.10.13")
            return True
        else:
            print(f"❌ runtime.txt contains incorrect version: {runtime}")
            return False
        
    except Exception as e:
        print(f"❌ Error reading runtime.txt: {e}")
        return False

def test_environment_variables():
    """Test environment variable handling"""
    print("🔍 Testing environment variable handling...")
    
    # Test default values
    test_vars = {
        'SECRET_KEY': 'default-dev-key-change-in-production',
        'ENCRYPTION_KEY': 'default-encryption-key-change-in-production',
        'DATABASE_URL': 'sqlite:///users.db'
    }
    
    for var_name, expected_default in test_vars.items():
        if var_name in os.environ:
            print(f"✅ {var_name} is set in environment")
        else:
            print(f"ℹ️ {var_name} not set, will use default: {expected_default}")
    
    return True

def test_file_structure():
    """Test if all required files exist"""
    print("🔍 Testing file structure...")
    
    required_files = [
        'render_app.py',
        'requirements_render.txt',
        'runtime.txt',
        '.gitignore',
        'README_Render.md'
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

def test_streamlit_run():
    """Test if the app can be run with streamlit"""
    print("🔍 Testing streamlit run command...")
    
    try:
        # Test the command that will be used on Render
        cmd = [sys.executable, '-m', 'streamlit', 'run', 'render_app.py', '--server.port', '8501', '--server.address', '0.0.0.0']
        
        # Start the process
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait a bit for startup
        import time
        time.sleep(3)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Streamlit app started successfully")
            process.terminate()
            process.wait()
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Streamlit app failed to start")
            print(f"STDOUT: {stdout.decode()}")
            print(f"STDERR: {stderr.decode()}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing streamlit run: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Road Report Nigeria - Render App Tests")
    print("=" * 50)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Module Imports", test_imports),
        ("Render App Syntax", test_render_app_syntax),
        ("Requirements", test_requirements),
        ("Runtime", test_runtime_txt),
        ("Environment Variables", test_environment_variables),
        ("Streamlit Run", test_streamlit_run)
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
        print("🎉 All tests passed! Your render app is ready for deployment!")
        print("\n🚀 Next steps:")
        print("1. Commit your changes to Git")
        print("2. Push to GitHub")
        print("3. Deploy to Render")
        print("4. Test the live deployment")
    else:
        print("❌ Some tests failed. Please fix the issues before deploying.")
        print("\n🔧 Common fixes:")
        print("- Check for syntax errors in render_app.py")
        print("- Ensure all required files exist")
        print("- Verify requirements_render.txt format")
        print("- Check Python version compatibility")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
