#!/usr/bin/env python3
"""
Startup script for Road Status Reporter Minimal App
"""
import os
import sys
import subprocess
import time
import webbrowser
from pathlib import Path

def print_banner():
    """Print application banner"""
    print("=" * 60)
    print("🚧 Road Status Reporter - Minimal App")
    print("=" * 60)
    print("A simple, clean road status reporting application")
    print("Built with Streamlit for easy deployment")
    print("=" * 60)

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = ["streamlit", "pandas", "plotly", "folium", "streamlit_folium"]
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} - Missing")
    
    if missing_packages:
        print(f"\n❌ Missing packages: {', '.join(missing_packages)}")
        print("Please install missing packages using:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    print("✅ All dependencies are installed!")
    return True

def start_minimal_app():
    """Start the minimal Streamlit app"""
    print("🚀 Starting Minimal App...")
    
    try:
        # Start Streamlit app
        process = subprocess.Popen([
            sys.executable, "-m", "streamlit", "run", "streamlit_app_minimal.py",
            "--server.port", "8501",
            "--server.address", "localhost"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait a moment for the app to start
        time.sleep(3)
        
        if process.poll() is None:
            print("✅ Minimal app started successfully!")
            return process
        else:
            print("❌ Failed to start minimal app")
            return None
            
    except Exception as e:
        print(f"❌ Error starting minimal app: {e}")
        return None

def open_browser():
    """Open the app in the default web browser"""
    print("🌐 Opening app in browser...")
    try:
        webbrowser.open("http://localhost:8501")
        print("✅ Browser opened!")
    except Exception as e:
        print(f"⚠️ Could not open browser automatically: {e}")
        print("Please open http://localhost:8501 in your browser")

def print_usage_info():
    """Print usage information"""
    print("\n" + "=" * 60)
    print("📱 MINIMAL APP IS RUNNING!")
    print("=" * 60)
    print("🌐 Open your browser and go to: http://localhost:8501")
    print("🔄 To stop the app, press Ctrl+C")
    print("📊 Features available:")
    print("   • Dashboard with metrics")
    print("   • View and filter reports")
    print("   • Create new reports")
    print("   • Interactive map view")
    print("   • Analytics and charts")
    print("=" * 60)

def main():
    """Main function"""
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Cannot start app due to missing dependencies")
        sys.exit(1)
    
    # Start the app
    app_process = start_minimal_app()
    if not app_process:
        print("\n❌ Failed to start minimal app")
        sys.exit(1)
    
    # Open browser
    open_browser()
    
    # Print usage info
    print_usage_info()
    
    try:
        print("\n🔄 Minimal app is running...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down Minimal App...")
        if app_process:
            app_process.terminate()
        print("👋 Minimal App shutdown complete")

if __name__ == "__main__":
    main()
