#!/usr/bin/env python3
"""
Deployment script for Nigerian Road Risk Reporter
Automates the process of pushing cleaned code to GitHub
"""

import subprocess
import os
import sys
from datetime import datetime

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def check_git_status():
    """Check if we're in a git repository"""
    if not os.path.exists('.git'):
        print("❌ Not in a git repository. Please initialize git first.")
        return False
    return True

def main():
    """Main deployment function"""
    print("🚀 Nigerian Road Risk Reporter - Deployment Script")
    print("=" * 60)
    
    # Check git status
    if not check_git_status():
        return False
    
    # Get current status
    print("📊 Current repository status:")
    run_command("git status", "Checking git status")
    
    # Add all files
    if not run_command("git add .", "Adding all files to git"):
        return False
    
    # Check what's staged
    print("📋 Files to be committed:")
    run_command("git status --porcelain", "Showing staged files")
    
    # Create commit message
    commit_message = f"""🚀 Deploy cleaned and optimized Road Risk Reporter

✅ Enhanced Security Features:
- Salted password hashing with SHA256
- Session management with automatic timeout
- Login attempt rate limiting
- Role-based access control (RBAC)
- Password strength validation

✅ Improved User Experience:
- Enhanced UI with better accessibility
- Responsive design for mobile devices
- Loading animations and user feedback
- Comprehensive error handling
- Session timeout notifications

✅ Python 3.13 Compatibility:
- Updated dependencies for Python 3.13
- Removed deprecated packages
- Optimized for Streamlit Cloud deployment
- Lightweight implementation

✅ Cleaned Codebase:
- Removed redundant files and modules
- Consolidated functionality
- Improved code organization
- Enhanced documentation

✅ AI Safety Advice Engine:
- Rule-based safety recommendations
- Location-aware risk analysis
- Time-based advice generation
- Database integration

✅ Analytics Dashboard:
- Interactive Plotly visualizations
- Real-time filtering capabilities
- CSV export functionality
- Comprehensive metrics

✅ PWA & Deployment Ready:
- Progressive Web App features
- SMS alert simulation
- Service worker implementation
- Streamlit Cloud optimized

🔧 Technical Improvements:
- Enhanced error handling and fallbacks
- Better session management
- Improved security logging
- Optimized database queries
- Mobile-responsive design

📅 Deployed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    # Commit changes
    if not run_command(f'git commit -m "{commit_message}"', "Committing changes"):
        return False
    
    # Push to GitHub
    if not run_command("git push origin main", "Pushing to GitHub"):
        return False
    
    print("\n🎉 Deployment completed successfully!")
    print("=" * 60)
    print("📋 Next steps:")
    print("1. ✅ Code pushed to GitHub")
    print("2. 🚀 Deploy to Streamlit Cloud:")
    print("   - Go to https://share.streamlit.io")
    print("   - Connect your GitHub repository")
    print("   - Set main file: streamlit_app_minimal.py")
    print("   - Deploy!")
    print("3. 🔧 Configure environment variables (optional)")
    print("4. 📱 Test PWA features")
    print("5. 🔒 Verify security features")
    
    return True

if __name__ == "__main__":
    success = main()
    if success:
        print("\n✅ Deployment script completed successfully!")
    else:
        print("\n❌ Deployment script failed!")
        sys.exit(1) 