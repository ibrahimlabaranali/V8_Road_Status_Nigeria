#!/usr/bin/env python3
"""
Deployment helper script for Road Report Nigeria - Render
This script helps prepare and verify your app for Render deployment
"""

import os
import sys
import subprocess

def check_git_status():
    """Check if we're in a git repository and if there are changes"""
    try:
        # Check if we're in a git repo
        result = subprocess.run(['git', 'status'], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Not in a git repository. Please initialize git first.")
            return False
        
        # Check for uncommitted changes
        result = subprocess.run(['git', 'diff', '--name-only'], capture_output=True, text=True)
        if result.stdout.strip():
            print("📝 Found uncommitted changes:")
            for file in result.stdout.strip().split('\n'):
                if file:
                    print(f"   - {file}")
            return True
        else:
            print("✅ No uncommitted changes found")
            return False
            
    except Exception as e:
        print(f"❌ Error checking git status: {e}")
        return False

def check_render_files():
    """Check if all required Render files exist"""
    required_files = [
        'render_app.py',
        'requirements_render.txt',
        'runtime.txt',
        '.gitignore',
        'README_Render.md'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {missing_files}")
        return False
    else:
        print("✅ All required Render files found")
        return True

def commit_changes():
    """Commit all changes to git"""
    try:
        print("📝 Adding all files to git...")
        subprocess.run(['git', 'add', '.'], check=True)
        
        print("📝 Committing changes...")
        commit_message = "Add Render deployment files - Clean and optimized version"
        subprocess.run(['git', 'commit', '-m', commit_message], check=True)
        
        print("✅ Changes committed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error committing changes: {e}")
        return False

def push_to_github():
    """Push changes to GitHub"""
    try:
        print("🚀 Pushing to GitHub...")
        subprocess.run(['git', 'push', 'origin', 'main'], check=True)
        print("✅ Successfully pushed to GitHub!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error pushing to GitHub: {e}")
        return False

def show_deployment_instructions():
    """Show deployment instructions"""
    print("\n" + "="*60)
    print("🚀 RENDER DEPLOYMENT INSTRUCTIONS")
    print("="*60)
    print("""
1. Go to [render.com](https://render.com) and sign up/login
2. Click "New +" and select "Web Service"
3. Connect your GitHub repository
4. Configure your service:
   - Name: road-report-nigeria (or your preferred name)
   - Runtime: Python 3
   - Build Command: pip install -r requirements_render.txt
   - Start Command: streamlit run render_app.py --server.port $PORT --server.address 0.0.0.0
5. Set environment variables (optional):
   - SECRET_KEY=your-secret-key
   - ENCRYPTION_KEY=your-encryption-key
   - DATABASE_URL=sqlite:///users.db
6. Click "Create Web Service"
7. Wait for deployment to complete
8. Test your live app!

Your app is now ready for Render deployment! 🎉
""")

def main():
    """Main deployment helper function"""
    print("🚀 Road Report Nigeria - Render Deployment Helper")
    print("="*50)
    
    # Check if we're ready for deployment
    if not check_render_files():
        print("❌ Cannot proceed - missing required files")
        return False
    
    if not check_git_status():
        print("ℹ️ No changes to commit")
    else:
        # Commit changes
        if not commit_changes():
            print("❌ Failed to commit changes")
            return False
    
    # Push to GitHub
    if not push_to_github():
        print("❌ Failed to push to GitHub")
        return False
    
    # Show deployment instructions
    show_deployment_instructions()
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
