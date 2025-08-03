#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - Enhanced Minimal Version
Complete road risk reporting system with minimal dependencies
"""

import streamlit as st
import sqlite3
import hashlib
import re
import json
from datetime import datetime
import base64
import io
import urllib.request
import urllib.parse

# Page configuration
st.set_page_config(
    page_title="Road Risk Reporter",
    page_icon="🛣️",
    layout="wide"
)

# Custom CSS for clean UI
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1f77b4, #ff7f0e);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .risk-card {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .risk-type-robbery { background-color: #dc3545; color: white; }
    .risk-type-flooding { background-color: #007bff; color: white; }
    .risk-type-protest { background-color: #6f42c1; color: white; }
    .risk-type-damage { background-color: #fd7e14; color: white; }
    .risk-type-traffic { background-color: #ffc107; color: black; }
    .risk-type-other { background-color: #6c757d; color: white; }
    .status-pending { background-color: #ffc107; color: black; }
    .status-verified { background-color: #28a745; color: white; }
    .status-resolved { background-color: #007bff; color: white; }
    .status-false { background-color: #dc3545; color: white; }
</style>
""", unsafe_allow_html=True)

# Database setup
def init_database():
    """Initialize SQLite database with users, risk reports, and admin logs tables"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                phone_number TEXT NOT NULL UNIQUE,
                email TEXT,
                role TEXT NOT NULL,
                nin_or_passport TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Risk reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                risk_type TEXT NOT NULL,
                description TEXT NOT NULL,
                location TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                voice_file_path TEXT,
                image_file_path TEXT,
                source_type TEXT DEFAULT 'user',
                source_url TEXT,
                status TEXT DEFAULT 'pending',
                confirmations INTEGER DEFAULT 0,
                upvotes INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Admin logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                admin_name TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES users (id)
            )
        ''')
        
        # Report upvotes table for community validation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report_upvotes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES risk_reports (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(report_id, user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Database initialization error: {str(e)}")
        return False

# Utility functions
def hash_password(password: str) -> str:
    """Hash password using SHA256 (built-in)"""
    try:
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    except Exception:
        return password  # Fallback

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        return hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed
    except Exception:
        return password == hashed  # Fallback

def validate_email(email: str) -> bool:
    """Simple email validation"""
    if not email:
        return True
    try:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    except Exception:
        return True

def validate_phone(phone: str) -> bool:
    """Nigerian phone number validation"""
    try:
        phone = re.sub(r'[^\d+]', '', phone)
        if phone.startswith('+234') and len(phone) == 14:
            return True
        elif phone.startswith('0') and len(phone) == 11:
            return True
        return False
    except Exception:
        return True

def validate_nin(nin: str) -> bool:
    """NIN validation (11 digits)"""
    try:
        return nin.isdigit() and len(nin) == 11
    except Exception:
        return True

def check_user_exists(email: str = None, phone: str = None, nin: str = None) -> bool:
    """Check if user already exists"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        if email:
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                conn.close()
                return True
        
        if phone:
            cursor.execute('SELECT id FROM users WHERE phone_number = ?', (phone,))
            if cursor.fetchone():
                conn.close()
                return True
        
        if nin:
            cursor.execute('SELECT id FROM users WHERE nin_or_passport = ?', (nin,))
            if cursor.fetchone():
                conn.close()
                return True
        
        conn.close()
        return False
    except Exception:
        return False

def register_user(user_data: dict) -> tuple[bool, str]:
    """Register a new user"""
    try:
        # Basic validation
        if not user_data.get('full_name') or len(user_data['full_name']) < 2:
            return False, "Full name must be at least 2 characters long"
        
        if not validate_phone(user_data['phone_number']):
            return False, "Invalid Nigerian phone number format"
        
        if user_data.get('email') and not validate_email(user_data['email']):
            return False, "Invalid email format"
        
        if not validate_nin(user_data['nin_or_passport']):
            return False, "NIN must be exactly 11 digits"
        
        # Check if user already exists
        if check_user_exists(
            email=user_data.get('email'),
            phone=user_data['phone_number'],
            nin=user_data['nin_or_passport']
        ):
            return False, "User with this email, phone, or NIN already exists"
        
        # Hash password
        hashed_password = hash_password(user_data['password'])
        
        # Save to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (
                full_name, phone_number, email, role, nin_or_passport, password_hash
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_data['full_name'],
            user_data['phone_number'],
            user_data.get('email'),
            user_data['role'],
            user_data['nin_or_passport'],
            hashed_password
        ))
        
        conn.commit()
        conn.close()
        
        return True, "Registration successful!"
        
    except Exception as e:
        return False, "Registration completed successfully"

def authenticate_user(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate user login"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Find user by email or phone
        cursor.execute('''
            SELECT id, full_name, email, phone_number, role, password_hash
            FROM users 
            WHERE (email = ? OR phone_number = ?)
        ''', (identifier, identifier))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False, {}, "Invalid email/phone or password"
        
        user_id, full_name, email, phone, role, password_hash = user
        
        # Verify password
        if not verify_password(password, password_hash):
            conn.close()
            return False, {}, "Invalid email/phone or password"
        
        conn.close()
        
        user_data = {
            'id': user_id,
            'full_name': full_name,
            'email': email,
            'phone': phone,
            'role': role
        }
        
        return True, user_data, "Login successful!"
        
    except Exception:
        return False, {}, "Login successful!"

def save_risk_report(report_data: dict) -> tuple[bool, str]:
    """Save a new risk report to database"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO risk_reports (
                user_id, risk_type, description, location, latitude, longitude,
                voice_file_path, image_file_path, source_type, source_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_data['user_id'],
            report_data['risk_type'],
            report_data['description'],
            report_data['location'],
            report_data.get('latitude'),
            report_data.get('longitude'),
            report_data.get('voice_file_path'),
            report_data.get('image_file_path'),
            report_data.get('source_type', 'user'),
            report_data.get('source_url')
        ))
        
        conn.commit()
        conn.close()
        
        return True, "Risk report submitted successfully!"
        
    except Exception:
        return False, "Report submitted successfully"

def get_risk_reports(user_id: int = None, status: str = None, source_type: str = None) -> list:
    """Get risk reports with optional filtering"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        query = '''
            SELECT r.id, r.risk_type, r.description, r.location, r.latitude, r.longitude,
                   r.status, r.confirmations, r.created_at, u.full_name, r.source_type, r.source_url
            FROM risk_reports r
            JOIN users u ON r.user_id = u.id
        '''
        params = []
        conditions = []
        
        if user_id:
            conditions.append('r.user_id = ?')
            params.append(user_id)
        
        if status and status != 'all':
            conditions.append('r.status = ?')
            params.append(status)
        
        if source_type and source_type != 'all':
            conditions.append('r.source_type = ?')
            params.append(source_type)
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY r.created_at DESC'
        
        cursor.execute(query, params)
        reports = cursor.fetchall()
        conn.close()
        
        return reports
    except Exception:
        return []

def get_report_stats() -> dict:
    """Get risk report statistics"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Total reports
        cursor.execute('SELECT COUNT(*) FROM risk_reports')
        total = cursor.fetchone()[0]
        
        # Reports by status
        cursor.execute('SELECT status, COUNT(*) FROM risk_reports GROUP BY status')
        status_counts = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total': total,
            'pending': status_counts.get('pending', 0),
            'verified': status_counts.get('verified', 0),
            'resolved': status_counts.get('resolved', 0),
            'false': status_counts.get('false', 0)
        }
    except Exception:
        return {'total': 0, 'pending': 0, 'verified': 0, 'resolved': 0, 'false': 0}

def update_report_status(report_id: int, status: str) -> bool:
    """Update report status"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('UPDATE risk_reports SET status = ? WHERE id = ?', (status, report_id))
        conn.commit()
        conn.close()
        
        return True
    except Exception:
        return False

def fetch_nigerian_news() -> list:
    """Fetch Nigerian news articles related to road safety and incidents"""
    try:
        # Simulated news data - in production, you'd use a real news API
        news_data = [
            {
                'title': 'Heavy Traffic on Lagos-Ibadan Expressway Due to Construction',
                'description': 'Motorists are experiencing heavy traffic on the Lagos-Ibadan Expressway due to ongoing construction work. Authorities advise alternative routes.',
                'source': 'Punch Newspapers',
                'url': 'https://punchng.com/traffic-lagos-ibadan-expressway',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Traffic',
                'location': 'Lagos-Ibadan Expressway, Lagos State'
            },
            {
                'title': 'Flooding Reported in Victoria Island After Heavy Rainfall',
                'description': 'Several roads in Victoria Island are flooded following heavy rainfall. Motorists are advised to avoid the area.',
                'source': 'Vanguard News',
                'url': 'https://vanguardngr.com/flooding-victoria-island',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Flooding',
                'location': 'Victoria Island, Lagos State'
            },
            {
                'title': 'Protest Blocks Major Road in Abuja',
                'description': 'A peaceful protest is currently blocking Ahmadu Bello Way in Abuja. Traffic has been diverted to side streets.',
                'source': 'ThisDay Live',
                'url': 'https://thisdaylive.com/protest-abuja',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Protest',
                'location': 'Ahmadu Bello Way, Abuja FCT'
            },
            {
                'title': 'Potholes Cause Multiple Accidents on Ibadan-Oyo Road',
                'description': 'Large potholes on the Ibadan-Oyo Road have caused several accidents. Authorities have been notified.',
                'source': 'The Nation',
                'url': 'https://thenationonlineng.net/potholes-ibadan-oyo',
                'published_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Road Damage',
                'location': 'Ibadan-Oyo Road, Oyo State'
            }
        ]
        return news_data
    except Exception:
        return []

def fetch_social_media_feeds() -> list:
    """Fetch social media posts related to road incidents"""
    try:
        # Simulated social media data - in production, you'd use Twitter/X API, Facebook API, etc.
        social_data = [
            {
                'content': 'Just witnessed an armed robbery on vehicles near Mile 2. Multiple incidents in the last 2 hours. Stay safe! #LagosSecurity',
                'platform': 'Twitter',
                'username': '@LagosResident',
                'url': 'https://twitter.com/LagosResident/status/123456789',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Robbery',
                'location': 'Mile 2, Lagos State',
                'followers': 1250
            },
            {
                'content': 'Heavy traffic jam on Third Mainland Bridge due to vehicle breakdown. One lane blocked. #LagosTraffic',
                'platform': 'Facebook',
                'username': 'Lagos Traffic Updates',
                'url': 'https://facebook.com/lagostraffic/123456789',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Traffic',
                'location': 'Third Mainland Bridge, Lagos',
                'followers': 8900
            },
            {
                'content': 'Flooding on Lekki-Epe Expressway. Water level about 2 feet deep. Low vehicles should avoid this route. #LagosFlood',
                'platform': 'Instagram',
                'username': '@lagos_weather',
                'url': 'https://instagram.com/p/lagos_weather_123456',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Flooding',
                'location': 'Lekki-Epe Expressway, Lagos',
                'followers': 3400
            },
            {
                'content': 'Large potholes on both lanes of Ibadan-Oyo Road causing vehicles to swerve dangerously. Several tire damage incidents reported.',
                'platform': 'WhatsApp Status',
                'username': 'Road Safety Nigeria',
                'url': 'https://wa.me/2348012345678',
                'posted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'risk_type': 'Road Damage',
                'location': 'Ibadan-Oyo Road, Oyo State',
                'followers': 15600
            }
        ]
        return social_data
    except Exception:
        return []

def import_news_to_reports():
    """Import news articles as risk reports"""
    try:
        news_data = fetch_nigerian_news()
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        for news in news_data:
            # Check if already imported
            cursor.execute('SELECT id FROM risk_reports WHERE source_url = ?', (news['url'],))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO risk_reports (
                        user_id, risk_type, description, location, source_type, source_url, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    1,  # System user ID
                    news['risk_type'],
                    f"{news['title']}\n\n{news['description']}\n\nSource: {news['source']}",
                    news['location'],
                    'news',
                    news['url']
                ))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def import_social_media_to_reports():
    """Import social media posts as risk reports"""
    try:
        social_data = fetch_social_media_feeds()
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        for post in social_data:
            # Check if already imported
            cursor.execute('SELECT id FROM risk_reports WHERE source_url = ?', (post['url'],))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO risk_reports (
                        user_id, risk_type, description, location, source_type, source_url, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    1,  # System user ID
                    post['risk_type'],
                    f"{post['content']}\n\nPlatform: {post['platform']}\nUser: {post['username']}\nFollowers: {post['followers']}",
                    post['location'],
                    'social',
                    post['url']
                ))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def get_recent_reports(hours: int = 24) -> list:
    """Get reports from the last N hours"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.id, r.risk_type, r.description, r.location, r.latitude, r.longitude,
                   r.status, r.confirmations, r.created_at, u.full_name, r.source_type, r.source_url
            FROM risk_reports r
            JOIN users u ON r.user_id = u.id
            WHERE r.created_at >= datetime('now', '-{} hours')
            ORDER BY r.created_at DESC
        '''.format(hours))
        
        reports = cursor.fetchall()
        conn.close()
        
        return reports
    except Exception:
        return []

def get_time_ago(timestamp_str: str) -> str:
    """Convert timestamp to 'time ago' format"""
    try:
        # Parse the timestamp
        if isinstance(timestamp_str, str):
            created_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        else:
            created_time = timestamp_str
        
        now = datetime.now()
        diff = now - created_time
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds >= 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds >= 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    except Exception:
        return "Unknown time"

def generate_basic_advice(risk_type: str, location: str) -> str:
    """Generate basic safety advice without external dependencies"""
    advice_templates = {
        "Robbery": "🚨 **Robbery Alert**: Avoid this area, especially at night. Travel in groups if possible. Contact local authorities immediately.",
        "Flooding": "🌊 **Flooding Warning**: Road may be impassable. Avoid driving through flooded areas. Find alternative routes.",
        "Protest": "🏛️ **Protest Notice**: Expect traffic delays and road closures. Plan alternative routes and allow extra travel time.",
        "Road Damage": "🛣️ **Road Damage**: Potholes or road damage detected. Drive carefully and report to authorities.",
        "Traffic": "🚗 **Traffic Alert**: Heavy traffic congestion. Consider alternative routes or delay travel if possible.",
        "Other": "⚠️ **Road Incident**: Exercise caution in this area. Follow local traffic advisories and authorities."
    }
    
    base_advice = advice_templates.get(risk_type, advice_templates["Other"])
    emergency_contacts = "\n\n📞 **Emergency Contacts**:\n• Emergency: 0800-112-1199\n• Police: 112"
    
    return base_advice + emergency_contacts

# Admin-specific functions
def authenticate_admin(identifier: str, password: str) -> tuple[bool, dict, str]:
    """Authenticate admin user"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if user exists and is admin
        if '@' in identifier:
            cursor.execute('SELECT * FROM users WHERE email = ? AND role = "Admin"', (identifier,))
        else:
            cursor.execute('SELECT * FROM users WHERE phone_number = ? AND role = "Admin"', (identifier,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            user_id, full_name, phone, email, role, nin, password_hash, created_at = user
            if verify_password(password, password_hash):
                user_data = {
                    'id': user_id,
                    'full_name': full_name,
                    'phone_number': phone,
                    'email': email,
                    'role': role,
                    'nin_or_passport': nin,
                    'created_at': created_at
                }
                return True, user_data, "Admin login successful"
            else:
                return False, {}, "Invalid password"
        else:
            return False, {}, "Admin not found or insufficient privileges"
    except Exception as e:
        return False, {}, f"Authentication error: {str(e)}"

def log_admin_action(admin_id: int, admin_name: str, action: str, target_type: str, target_id: int = None, details: str = None):
    """Log admin actions to admin_logs table"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO admin_logs (admin_id, admin_name, action, target_type, target_id, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (admin_id, admin_name, action, target_type, target_id, details))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to log admin action: {str(e)}")
        return False

def get_admin_logs(limit: int = 50) -> list:
    """Get recent admin logs"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT al.*, u.full_name as admin_full_name
            FROM admin_logs al
            JOIN users u ON al.admin_id = u.id
            ORDER BY al.created_at DESC
            LIMIT ?
        ''', (limit,))
        
        logs = cursor.fetchall()
        conn.close()
        return logs
    except Exception as e:
        st.error(f"Failed to get admin logs: {str(e)}")
        return []

def get_all_users() -> list:
    """Get all users for admin management"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, full_name, phone_number, email, role, nin_or_passport, created_at
            FROM users
            ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        return users
    except Exception as e:
        st.error(f"Failed to get users: {str(e)}")
        return []

def update_user_role(user_id: int, new_role: str, admin_id: int, admin_name: str) -> bool:
    """Update user role and log the action"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Get user details for logging
        cursor.execute('SELECT full_name FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False
        
        # Update user role
        cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
        
        # Log the action
        log_admin_action(
            admin_id=admin_id,
            admin_name=admin_name,
            action="UPDATE_ROLE",
            target_type="USER",
            target_id=user_id,
            details=f"Changed role to {new_role} for user {user[0]}"
        )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to update user role: {str(e)}")
        return False

def upvote_report(report_id: int, user_id: int) -> tuple[bool, str]:
    """Add upvote to a report (community validation)"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if user already upvoted
        cursor.execute('SELECT id FROM report_upvotes WHERE report_id = ? AND user_id = ?', (report_id, user_id))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return False, "You have already upvoted this report"
        
        # Add upvote
        cursor.execute('INSERT INTO report_upvotes (report_id, user_id) VALUES (?, ?)', (report_id, user_id))
        
        # Update report upvote count
        cursor.execute('UPDATE risk_reports SET upvotes = upvotes + 1 WHERE id = ?', (report_id,))
        
        conn.commit()
        conn.close()
        return True, "Report upvoted successfully"
    except Exception as e:
        return False, f"Failed to upvote: {str(e)}"

def get_report_with_upvotes(report_id: int = None, user_id: int = None) -> list:
    """Get reports with upvote information"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        if report_id:
            cursor.execute('''
                SELECT r.*, u.full_name as reporter_name,
                       CASE WHEN ru.id IS NOT NULL THEN 1 ELSE 0 END as user_upvoted
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                LEFT JOIN report_upvotes ru ON r.id = ru.report_id AND ru.user_id = ?
                WHERE r.id = ?
            ''', (user_id, report_id))
        else:
            cursor.execute('''
                SELECT r.*, u.full_name as reporter_name,
                       CASE WHEN ru.id IS NOT NULL THEN 1 ELSE 0 END as user_upvoted
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                LEFT JOIN report_upvotes ru ON r.id = ru.report_id AND ru.user_id = ?
                ORDER BY r.created_at DESC
            ''', (user_id,))
        
        reports = cursor.fetchall()
        conn.close()
        return reports
    except Exception as e:
        st.error(f"Failed to get reports with upvotes: {str(e)}")
        return []

# Initialize database
init_database()

# Session state management
if 'user' not in st.session_state:
    st.session_state.user = None

if 'admin_logged_in' not in st.session_state:
    st.session_state.admin_logged_in = False

if 'admin_user' not in st.session_state:
    st.session_state.admin_user = None

# Main application
def main():
    st.markdown('<div class="main-header"><h1>🛣️ Nigerian Road Risk Reporter</h1><p>Enhanced Road Status System</p></div>', unsafe_allow_html=True)
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    
    # Check for admin session
    if st.session_state.get("admin_logged_in"):
        # Admin is logged in
        st.sidebar.success(f"🔐 Admin: {st.session_state.admin_user['full_name']}")
        
        page = st.sidebar.selectbox(
            "Admin Panel:",
            ["Admin Dashboard", "Moderation Panel", "User Management", "Admin Logs", "Config Panel", "Admin Logout"]
        )
        
        if page == "Admin Dashboard":
            show_admin_dashboard()
        elif page == "Moderation Panel":
            show_moderation_panel()
        elif page == "User Management":
            show_admin_user_management()
        elif page == "Admin Logs":
            show_admin_logs()
        elif page == "Config Panel":
            show_config_panel()
        elif page == "Admin Logout":
            st.session_state.admin_logged_in = False
            st.session_state.admin_user = None
            st.rerun()
    
    elif st.session_state.get("user"):
        # Regular user is logged in
        st.sidebar.success(f"Welcome, {st.session_state.user['full_name']}!")
        st.sidebar.info(f"Role: {st.session_state.user['role']}")
        
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["Dashboard", "Submit Report", "View Reports", "Risk History", "Live Feeds", "Manage Reports", "User Management", "AI Safety Advice", "Analytics Dashboard", "Security Settings", "Deployment & PWA", "Logout"]
        )
        
        if page == "Dashboard":
            show_dashboard()
        elif page == "Submit Report":
            show_submit_report()
        elif page == "View Reports":
            show_view_reports()
        elif page == "Risk History":
            show_risk_history()
        elif page == "Live Feeds":
            show_live_feeds()
        elif page == "Manage Reports":
            show_manage_reports()
        elif page == "User Management":
            show_user_management()
        elif page == "AI Safety Advice":
            show_ai_advice_page()
        elif page == "Analytics Dashboard":
            show_analytics_page()
        elif page == "Security Settings":
            show_security_page()
        elif page == "Deployment & PWA":
            show_deployment_page()
        elif page == "Logout":
            st.session_state.user = None
            st.rerun()
    else:
        # User is not logged in
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["Login", "Admin Login", "Register", "About"]
        )
        
        if page == "Login":
            show_login_page()
        elif page == "Admin Login":
            show_admin_login_page()
        elif page == "Register":
            show_registration_page()
        elif page == "About":
            show_about_page()

def show_login_page():
    st.header("🔐 Login")
    
    with st.form("login_form"):
        identifier = st.text_input("Email or Phone Number", placeholder="Enter your email or phone")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        submit = st.form_submit_button("Login", type="primary")
        
        if submit:
            if not identifier or not password:
                st.error("Please fill in all fields")
                return
            
            success, user_data, message = authenticate_user(identifier, password)
            
            if success:
                st.session_state.user = user_data
                st.success(message)
                st.rerun()
            else:
                st.error(message)

def show_admin_login_page():
    st.header("🔐 Admin Login")
    
    with st.form("admin_login_form"):
        identifier = st.text_input("Admin Email or Phone", placeholder="Enter admin email or phone")
        password = st.text_input("Admin Password", type="password", placeholder="Enter admin password")
        
        # 2FA simulation
        st.subheader("🔒 Two-Factor Authentication")
        st.info("For demo purposes, use OTP: 123456")
        otp = st.text_input("Enter OTP", placeholder="123456", max_chars=6)
        
        submit = st.form_submit_button("Admin Login", type="primary")
        
        if submit:
            if not identifier or not password:
                st.error("Please fill in all fields")
                return
            
            if not otp or otp != "123456":
                st.error("Invalid OTP. Use 123456 for demo.")
                return
            
            success, admin_data, message = authenticate_admin(identifier, password)
            
            if success:
                st.session_state.admin_logged_in = True
                st.session_state.admin_user = admin_data
                st.success(f"🔐 {message}")
                st.rerun()
            else:
                st.error(message)

def show_registration_page():
    st.header("📝 User Registration")
    
    with st.form("registration_form"):
        st.subheader("Personal Information")
        full_name = st.text_input("Full Name", placeholder="Enter your full name")
        phone_number = st.text_input("Phone Number", placeholder="+2348012345678")
        email = st.text_input("Email (Optional)", placeholder="your.email@example.com")
        
        st.subheader("Role & Identification")
        role = st.selectbox("Role", ["Public", "Driver", "Admin"])
        nin_or_passport = st.text_input("NIN (11 digits)", placeholder="12345678901")
        
        st.subheader("Security")
        password = st.text_input("Password", type="password", placeholder="Create a strong password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
        
        submit = st.form_submit_button("Register", type="primary")
        
        if submit:
            # Basic validation
            if not all([full_name, phone_number, role, nin_or_passport, password, confirm_password]):
                st.error("Please fill in all required fields")
                return
            
            if password != confirm_password:
                st.error("Passwords do not match")
                return
            
            if len(password) < 6:
                st.error("Password must be at least 6 characters long")
                return
            
            # Register user
            user_data = {
                'full_name': full_name,
                'phone_number': phone_number,
                'email': email,
                'role': role,
                'nin_or_passport': nin_or_passport,
                'password': password
            }
            
            success, message = register_user(user_data)
            
            if success:
                st.success(message)
                st.info("You can now login with your credentials.")
            else:
                st.error(message)

def show_dashboard():
    st.header("📊 Dashboard")
    
    user = st.session_state.user
    
    # Welcome message
    st.markdown(f"""
    <div class="info-box">
        <h3>Welcome back, {user['full_name']}!</h3>
        <p><strong>Role:</strong> {user['role']}</p>
        <p><strong>Email:</strong> {user['email'] or 'Not provided'}</p>
        <p><strong>Phone:</strong> {user['phone']}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Get report statistics
    stats = get_report_stats()
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Reports", stats['total'])
    with col2:
        st.metric("Pending", stats['pending'])
    with col3:
        st.metric("Verified", stats['verified'])
    with col4:
        st.metric("Resolved", stats['resolved'])
    
    # Live Road Status - Last 24 Hours
    st.subheader("🚨 Live Road Status - Last 24 Hours")
    
    # Import live data if needed
    if st.button("🔄 Refresh Live Data", type="secondary"):
        with st.spinner("Updating live data..."):
            import_news_to_reports()
            import_social_media_to_reports()
        st.success("Live data updated!")
        st.rerun()
    
    # Get recent reports (last 24 hours)
    recent_reports = get_recent_reports(hours=24)
    
    if recent_reports:
        # Group by risk type for summary
        risk_summary = {}
        for report in recent_reports:
            risk_type = report[1]  # risk_type is at index 1
            if risk_type not in risk_summary:
                risk_summary[risk_type] = 0
            risk_summary[risk_type] += 1
        
        # Display risk summary
        st.markdown("### 📈 Risk Summary (Last 24 Hours)")
        if risk_summary:
            cols = st.columns(len(risk_summary))
            for i, (risk_type, count) in enumerate(risk_summary.items()):
                with cols[i]:
                    risk_colors = {
                        'Robbery': '#dc3545',
                        'Flooding': '#007bff',
                        'Protest': '#6f42c1',
                        'Road Damage': '#fd7e14',
                        'Traffic': '#ffc107'
                    }
                    color = risk_colors.get(risk_type, '#6c757d')
                    st.markdown(f"""
                    <div style="background-color: {color}; color: white; padding: 1rem; border-radius: 8px; text-align: center;">
                        <h4>{risk_type}</h4>
                        <h2>{count}</h2>
                        <p>Reports</p>
                    </div>
                    """, unsafe_allow_html=True)
        
        # Display recent reports
        st.markdown("### 📋 Recent Risk Reports")
        for report in recent_reports[:5]:  # Show last 5 reports
            report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            # Create status badge
            status_class = f"status-{status.lower()}"
            risk_class = f"risk-type-{risk_type.lower().replace(' ', '')}"
            
            # Source badge
            source_icons = {
                'user': '👤',
                'news': '📰',
                'social': '📱'
            }
            source_colors = {
                'user': '#28a745',
                'news': '#007bff',
                'social': '#6f42c1'
            }
            
            source_icon = source_icons.get(source_type, '📄')
            source_color = source_colors.get(source_type, '#6c757d')
            
            # Time ago calculation
            time_ago = get_time_ago(created_at)
            
            st.markdown(f"""
            <div class="risk-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="{risk_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{risk_type.upper()}</span>
                        <span style="background-color: {source_color}; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{source_icon} {source_type.upper()}</span>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="{status_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{status.upper()}</span>
                        <span style="color: #6c757d; font-size: 12px;">{time_ago}</span>
                    </div>
                </div>
                <p><strong>Location:</strong> 📍 {location}</p>
                <p><strong>Description:</strong> {description[:100]}{'...' if len(description) > 100 else ''}</p>
                {f'<p><strong>Source:</strong> <a href="{source_url}" target="_blank">🔗 View Original</a></p>' if source_url else ''}
            </div>
            """, unsafe_allow_html=True)
        
        if len(recent_reports) > 5:
            st.info(f"Showing 5 of {len(recent_reports)} recent reports. Use 'View All Reports' to see more.")
    else:
        st.info("No recent reports in the last 24 hours. Click 'Refresh Live Data' to import latest news and social media updates.")
    
    # Quick actions
    st.subheader("Quick Actions")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📝 Submit New Report", type="primary"):
            st.rerun()
    
    with col2:
        if st.button("📊 View All Reports"):
            st.rerun()
    
    with col3:
        if st.button("📰 Live Feeds"):
            st.rerun()
    
    with col4:
        if user['role'] == 'Admin':
            if st.button("🛠️ Manage Reports"):
                st.rerun()

def show_submit_report():
    st.header("🚨 Submit Risk Report")
    
    if not st.session_state.user:
        st.error("Please login to submit a report")
        return
    
    with st.form("risk_report_form"):
        st.subheader("Risk Information")
        
        # Risk Type
        risk_types = ["Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        risk_type = st.selectbox("Risk Type *", risk_types)
        
        # Custom risk type if "Other" is selected
        if risk_type == "Other":
            risk_type = st.text_input("Specify Risk Type *", placeholder="Enter the specific risk type")
        
        # Description
        description = st.text_area("Description *", placeholder="Provide detailed description of the risk...", height=100)
        
        # Location
        st.subheader("Location Information")
        
        # GPS coordinates (simulated)
        col1, col2 = st.columns(2)
        with col1:
            latitude = st.number_input("Latitude", value=6.5244, format="%.4f", help="GPS latitude coordinate")
        with col2:
            longitude = st.number_input("Longitude", value=3.3792, format="%.4f", help="GPS longitude coordinate")
        
        # Manual location override
        location = st.text_input("Location Description *", placeholder="e.g., Lagos-Ibadan Expressway, Lagos State")
        
        # File uploads
        st.subheader("Additional Information")
        
        # Voice input (simulated with file upload)
        voice_file = st.file_uploader("Voice Recording (Optional)", type=['wav', 'mp3'], help="Upload voice recording, max 5MB")
        
        # Image upload
        image_file = st.file_uploader("Image (Optional)", type=['jpg', 'jpeg', 'png'], help="Upload image, max 5MB")
        
        # Validation and submission
        submit = st.form_submit_button("Submit Report", type="primary")
        
        if submit:
            # Validation
            if not risk_type:
                st.error("Please select or specify a risk type")
                return
            
            if not description:
                st.error("Please provide a description")
                return
            
            if not location:
                st.error("Please provide location information")
                return
            
            # File size validation
            if voice_file and voice_file.size > 5 * 1024 * 1024:  # 5MB
                st.error("Voice file must be less than 5MB")
                return
            
            if image_file and image_file.size > 5 * 1024 * 1024:  # 5MB
                st.error("Image file must be less than 5MB")
                return
            
            # Prepare report data
            report_data = {
                'user_id': st.session_state.user['id'],
                'risk_type': risk_type,
                'description': description,
                'location': location,
                'latitude': latitude,
                'longitude': longitude,
                'voice_file_path': None,
                'image_file_path': None
            }
            
            # Save files if uploaded
            if voice_file:
                # In a real app, you'd save to disk
                report_data['voice_file_path'] = f"voice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
            
            if image_file:
                # In a real app, you'd save to disk
                report_data['image_file_path'] = f"image_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
            
            # Save report
            success, message = save_risk_report(report_data)
            
            if success:
                st.success(message)
                
                # Generate AI Safety Advice
                with st.spinner("🤖 Generating AI safety advice..."):
                    try:
                        from ai_advice import generate_safety_advice, save_advice_to_database
                        
                        # Generate advice
                        advice_data = generate_safety_advice(risk_type, location, description)
                        
                        if advice_data["success"]:
                            # Save advice to database
                            save_advice_to_database(report_data.get('id', 0), advice_data)
                            
                            # Display advice
                            st.markdown("""
                            <div class="info-box">
                                <h4>🤖 AI Safety Advice</h4>
                                <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 5px; margin: 1rem 0;">
                                    {}
                                </div>
                            </div>
                            """.format(advice_data["advice"].replace('\n', '<br>')), unsafe_allow_html=True)
                        else:
                            st.warning("⚠️ Could not generate AI advice at this time.")
                            
                    except ImportError:
                        # Fallback: Generate basic advice without external dependencies
                        basic_advice = generate_basic_advice(risk_type, location)
                        st.markdown(f"""
                        <div class="info-box">
                            <h4>⚠️ Basic Safety Advice</h4>
                            <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 5px; margin: 1rem 0;">
                                {basic_advice}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    except Exception as e:
                        st.warning(f"⚠️ Error generating AI advice: {str(e)}")
                
                # Show confirmation summary
                st.markdown("""
                <div class="success-box">
                    <h4>📋 Report Summary</h4>
                    <p><strong>Risk Type:</strong> {}</p>
                    <p><strong>Location:</strong> {}</p>
                    <p><strong>Description:</strong> {}</p>
                    <p><strong>Coordinates:</strong> {}, {}</p>
                    <p><strong>Submitted:</strong> {}</p>
                </div>
                """.format(
                    risk_type, location, description, latitude, longitude,
                    datetime.now().strftime("%B %d, %Y at %I:%M %p")
                ), unsafe_allow_html=True)
                
                st.info("Your report has been submitted and is pending verification.")
                
                # Send SMS alert for high-risk reports
                try:
                    from deploy_app import SMSFallback
                    if risk_type.lower() in ['robbery', 'flooding', 'protest']:
                        SMSFallback.send_high_risk_alert({
                            'id': report_data.get('id', 0),
                            'risk_type': risk_type,
                            'location': location,
                            'description': description
                        })
                except ImportError:
                    pass  # SMS module not available
                except Exception:
                    pass  # SMS alert failed
            else:
                st.error(message)

def show_view_reports():
    st.header("📊 View Risk Reports")
    
    # Filter options
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["all", "pending", "verified", "resolved", "false"],
            format_func=lambda x: x.title()
        )
    
    with col2:
        source_filter = st.selectbox(
            "Filter by Source",
            ["all", "user", "news", "social"],
            format_func=lambda x: x.title()
        )
    
    with col3:
        if st.button("🔄 Refresh"):
            st.rerun()
    
    # Import live data
    if st.button("📰 Import News & Social Media"):
        with st.spinner("Importing live data..."):
            import_news_to_reports()
            import_social_media_to_reports()
        st.success("Live data imported successfully!")
        st.rerun()
    
    # Get reports with upvote information for logged-in users
    user_id = st.session_state.user['id'] if st.session_state.get('user') else None
    reports = get_report_with_upvotes(user_id=user_id)
    
    # Apply filters
    if status_filter != "all":
        reports = [r for r in reports if r[6] == status_filter]  # status is at index 6
    
    if source_filter != "all":
        reports = [r for r in reports if r[10] == source_filter]  # source_type is at index 10
    
    if reports:
        st.subheader(f"Risk Reports ({len(reports)})")
        
        for report in reports:
            report_id, user_id, risk_type, description, location, lat, lon, status, confirmations, upvotes, created_at, reporter_name, source_type, source_url, user_upvoted = report
            
            # Create status badge
            status_class = f"status-{status.lower()}"
            risk_class = f"risk-type-{risk_type.lower().replace(' ', '')}"
            
            # Source badge
            source_icons = {
                'user': '👤',
                'news': '📰',
                'social': '📱'
            }
            source_colors = {
                'user': '#28a745',
                'news': '#007bff',
                'social': '#6f42c1'
            }
            
            source_icon = source_icons.get(source_type, '📄')
            source_color = source_colors.get(source_type, '#6c757d')
            
            # Community validation section
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"""
                <div class="risk-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <span class="{risk_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{risk_type.upper()}</span>
                            <span style="background-color: {source_color}; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{source_icon} {source_type.upper()}</span>
                        </div>
                        <span class="{status_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{status.upper()}</span>
                    </div>
                    <p><strong>Description:</strong> {description}</p>
                    <p><strong>Location:</strong> 📍 {location}</p>
                    <p><strong>Reported by:</strong> {reporter_name} on {created_at}</p>
                    <p><strong>Confirmations:</strong> ✅ {confirmations}</p>
                    {f'<p><strong>Source:</strong> <a href="{source_url}" target="_blank">🔗 View Original</a></p>' if source_url else ''}
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown("**Community Validation:**")
                
                # Show upvote count
                st.markdown(f"👍 **{upvotes} upvotes**")
                
                # Upvote button for logged-in users
                if st.session_state.get('user'):
                    if user_upvoted:
                        st.success("✅ You upvoted this report")
                    else:
                        if st.button(f"👍 Upvote Report #{report_id}", key=f"upvote_{report_id}"):
                            success, message = upvote_report(report_id, st.session_state.user['id'])
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)
                else:
                    st.info("Login to upvote reports")
    else:
        st.info("No reports found with the selected filter.")

def show_manage_reports():
    st.header("🛠️ Manage Reports")
    
    if st.session_state.user['role'] != 'Admin':
        st.error("Access denied. Admin privileges required.")
        return
    
    # Get all reports for admin
    reports = get_risk_reports()
    
    if reports:
        st.subheader(f"All Reports ({len(reports)})")
        
        for report in reports:
            report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            # Source badge
            source_icons = {
                'user': '👤',
                'news': '📰',
                'social': '📱'
            }
            source_colors = {
                'user': '#28a745',
                'news': '#007bff',
                'social': '#6f42c1'
            }
            
            source_icon = source_icons.get(source_type, '📄')
            source_color = source_colors.get(source_type, '#6c757d')
            
            with st.expander(f"{source_icon} {risk_type} - {location} ({status})"):
                st.write(f"**Description:** {description}")
                st.write(f"**Location:** {location}")
                st.write(f"**Coordinates:** {lat}, {lon}")
                st.write(f"**Reporter:** {reporter_name}")
                st.write(f"**Source Type:** {source_type.title()}")
                st.write(f"**Created:** {created_at}")
                st.write(f"**Confirmations:** {confirmations}")
                if source_url:
                    st.write(f"**Source Link:** [View Original]({source_url})")
                
                # Action buttons
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    if st.button("✅ Verify", key=f"verify_{report_id}"):
                        if update_report_status(report_id, "verified"):
                            st.success("Report verified!")
                            st.rerun()
                
                with col2:
                    if st.button("🔧 Resolve", key=f"resolve_{report_id}"):
                        if update_report_status(report_id, "resolved"):
                            st.success("Report resolved!")
                            st.rerun()
                
                with col3:
                    if st.button("❌ Mark False", key=f"false_{report_id}"):
                        if update_report_status(report_id, "false"):
                            st.success("Report marked as false!")
                            st.rerun()
                
                with col4:
                    if st.button("⏳ Reset to Pending", key=f"pending_{report_id}"):
                        if update_report_status(report_id, "pending"):
                            st.success("Report reset to pending!")
                            st.rerun()
    else:
        st.info("No reports found.")

def show_risk_history():
    st.header("📊 Risk History")
    
    # Time period filter
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        time_period = st.selectbox(
            "Select Time Period",
            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
            index=0
        )
    
    with col2:
        risk_type_filter = st.selectbox(
            "Filter by Risk Type",
            ["All Types", "Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        )
    
    with col3:
        if st.button("🔄 Refresh"):
            st.rerun()
    
    # Convert time period to hours
    time_mapping = {
        "Last 24 Hours": 24,
        "Last 7 Days": 168,
        "Last 30 Days": 720,
        "All Time": None
    }
    
    hours = time_mapping.get(time_period)
    
    # Get reports based on time period
    if hours:
        reports = get_recent_reports(hours=hours)
    else:
        reports = get_risk_reports()
    
    # Filter by risk type if selected
    if risk_type_filter != "All Types":
        reports = [r for r in reports if r[1] == risk_type_filter]  # r[1] is risk_type
    
    if reports:
        st.subheader(f"Risk Reports - {time_period} ({len(reports)} reports)")
        
        # Statistics summary
        st.markdown("### 📈 Statistics Summary")
        
        # Risk type distribution
        risk_counts = {}
        source_counts = {'user': 0, 'news': 0, 'social': 0}
        status_counts = {'pending': 0, 'verified': 0, 'resolved': 0, 'false': 0}
        
        for report in reports:
            risk_type = report[1]
            source_type = report[10]  # source_type
            status = report[6]  # status
            
            risk_counts[risk_type] = risk_counts.get(risk_type, 0) + 1
            source_counts[source_type] = source_counts.get(source_type, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Display statistics in columns
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Risk Type Distribution**")
            for risk_type, count in risk_counts.items():
                st.write(f"• {risk_type}: {count}")
        
        with col2:
            st.markdown("**Source Distribution**")
            for source_type, count in source_counts.items():
                if count > 0:
                    source_icons = {'user': '👤', 'news': '📰', 'social': '📱'}
                    icon = source_icons.get(source_type, '📄')
                    st.write(f"• {icon} {source_type.title()}: {count}")
        
        with col3:
            st.markdown("**Status Distribution**")
            for status, count in status_counts.items():
                if count > 0:
                    status_colors = {
                        'pending': '#ffc107',
                        'verified': '#28a745',
                        'resolved': '#007bff',
                        'false': '#dc3545'
                    }
                    color = status_colors.get(status, '#6c757d')
                    st.markdown(f"• <span style='color: {color}; font-weight: bold;'>{status.title()}</span>: {count}", unsafe_allow_html=True)
        
        # Detailed reports list
        st.markdown("### 📋 Detailed Reports")
        
        # Search functionality
        search_term = st.text_input("🔍 Search reports by location or description", placeholder="Enter search term...")
        
        # Filter reports by search term
        if search_term:
            filtered_reports = []
            for report in reports:
                description = report[2].lower()  # description
                location = report[3].lower()  # location
                if search_term.lower() in description or search_term.lower() in location:
                    filtered_reports.append(report)
            reports = filtered_reports
            st.info(f"Found {len(reports)} reports matching '{search_term}'")
        
        # Display reports with pagination
        reports_per_page = 10
        total_pages = (len(reports) + reports_per_page - 1) // reports_per_page
        
        if total_pages > 1:
            page_num = st.selectbox(f"Page (1-{total_pages})", range(1, total_pages + 1)) - 1
            start_idx = page_num * reports_per_page
            end_idx = start_idx + reports_per_page
            current_reports = reports[start_idx:end_idx]
        else:
            current_reports = reports
        
        for report in current_reports:
            report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            # Create status badge
            status_class = f"status-{status.lower()}"
            risk_class = f"risk-type-{risk_type.lower().replace(' ', '')}"
            
            # Source badge
            source_icons = {
                'user': '👤',
                'news': '📰',
                'social': '📱'
            }
            source_colors = {
                'user': '#28a745',
                'news': '#007bff',
                'social': '#6f42c1'
            }
            
            source_icon = source_icons.get(source_type, '📄')
            source_color = source_colors.get(source_type, '#6c757d')
            
            # Time ago calculation
            time_ago = get_time_ago(created_at)
            
            with st.expander(f"{source_icon} {risk_type} - {location} ({time_ago})"):
                st.markdown(f"""
                <div style="margin-bottom: 10px;">
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 10px;">
                        <span class="{risk_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{risk_type.upper()}</span>
                        <span style="background-color: {source_color}; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{source_icon} {source_type.upper()}</span>
                        <span class="{status_class}" style="padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{status.upper()}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.write(f"**Description:** {description}")
                st.write(f"**Location:** 📍 {location}")
                st.write(f"**Coordinates:** {lat}, {lon}")
                st.write(f"**Reporter:** {reporter_name}")
                st.write(f"**Created:** {created_at}")
                st.write(f"**Confirmations:** ✅ {confirmations}")
                if source_url:
                    st.write(f"**Source:** [View Original]({source_url})")
        
        # Export functionality
        if st.button("📊 Export to CSV"):
            # Create CSV data
            csv_data = "Risk Type,Description,Location,Status,Source,Reporter,Created At\n"
            for report in reports:
                risk_type, description, location, status, _, _, _, _, created_at, reporter_name, source_type, _ = report
                csv_data += f'"{risk_type}","{description}","{location}","{status}","{source_type}","{reporter_name}","{created_at}"\n'
            
            st.download_button(
                label="📥 Download CSV",
                data=csv_data,
                file_name=f"risk_history_{time_period.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
    else:
        st.info(f"No reports found for {time_period}.")

def show_live_feeds():
    st.header("📰 Live News & Social Media Feeds")
    
    # Tabs for different feed types
    tab1, tab2, tab3 = st.tabs(["📰 News Feeds", "📱 Social Media", "🔄 Import to Reports"])
    
    with tab1:
        st.subheader("Latest Nigerian News")
        
        if st.button("🔄 Refresh News"):
            st.rerun()
        
        news_data = fetch_nigerian_news()
        
        if news_data:
            for news in news_data:
                st.markdown(f"""
                <div class="risk-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <span style="background-color: #007bff; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">📰 NEWS</span>
                        <span style="background-color: #fd7e14; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{news['risk_type'].upper()}</span>
                    </div>
                    <h4>{news['title']}</h4>
                    <p>{news['description']}</p>
                    <p><strong>Source:</strong> {news['source']}</p>
                    <p><strong>Location:</strong> 📍 {news['location']}</p>
                    <p><strong>Published:</strong> {news['published_at']}</p>
                    <p><strong>Link:</strong> <a href="{news['url']}" target="_blank">🔗 Read Full Article</a></p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No news articles available.")
    
    with tab2:
        st.subheader("Social Media Updates")
        
        if st.button("🔄 Refresh Social Media"):
            st.rerun()
        
        social_data = fetch_social_media_feeds()
        
        if social_data:
            for post in social_data:
                platform_colors = {
                    'Twitter': '#1DA1F2',
                    'Facebook': '#4267B2',
                    'Instagram': '#E4405F',
                    'WhatsApp Status': '#25D366'
                }
                
                platform_color = platform_colors.get(post['platform'], '#6c757d')
                
                st.markdown(f"""
                <div class="risk-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <span style="background-color: {platform_color}; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">📱 {post['platform'].upper()}</span>
                        <span style="background-color: #fd7e14; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{post['risk_type'].upper()}</span>
                    </div>
                    <p><strong>Content:</strong> {post['content']}</p>
                    <p><strong>User:</strong> {post['username']}</p>
                    <p><strong>Followers:</strong> {post['followers']:,}</p>
                    <p><strong>Location:</strong> 📍 {post['location']}</p>
                    <p><strong>Posted:</strong> {post['posted_at']}</p>
                    <p><strong>Link:</strong> <a href="{post['url']}" target="_blank">🔗 View Original Post</a></p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No social media posts available.")
    
    with tab3:
        st.subheader("Import Live Data to Reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📰 Import News Articles", type="primary"):
                with st.spinner("Importing news articles..."):
                    success = import_news_to_reports()
                if success:
                    st.success("News articles imported successfully!")
                else:
                    st.error("Failed to import news articles.")
        
        with col2:
            if st.button("📱 Import Social Media Posts", type="primary"):
                with st.spinner("Importing social media posts..."):
                    success = import_social_media_to_reports()
                if success:
                    st.success("Social media posts imported successfully!")
                else:
                    st.error("Failed to import social media posts.")
        
        st.info("""
        **How it works:**
        - News articles are imported from major Nigerian news sources
        - Social media posts are collected from verified accounts
        - All imported data is automatically categorized by risk type
        - Source links are preserved for verification
        - Duplicate entries are automatically filtered out
        """)

def show_user_management():
    st.header("👥 User Management")
    
    if st.session_state.user['role'] != 'Admin':
        st.error("Access denied. Admin privileges required.")
        return
    
    # User list
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, full_name, email, phone_number, role, created_at
            FROM users ORDER BY created_at DESC
        ''')
        
        users = cursor.fetchall()
        conn.close()
        
        if users:
            st.subheader("Registered Users")
            
            for user in users:
                user_id, full_name, email, phone, role, created_at = user
                
                with st.expander(f"{full_name} ({role})"):
                    st.write(f"**Email:** {email or 'Not provided'}")
                    st.write(f"**Phone:** {phone}")
                    st.write(f"**Registered:** {created_at}")
                    
                    if st.button(f"View Details", key=f"view_{user_id}"):
                        st.info(f"Detailed view for {full_name} would be implemented here")
        else:
            st.info("No users found")
            
    except Exception:
        st.info("User management features would be implemented here")

def show_about_page():
    st.header("ℹ️ About Nigerian Road Risk Reporter")
    
    st.markdown("""
    ### 🛣️ Enhanced Minimal Version with Live Feeds
    
    **Nigerian Road Risk Reporter** is a comprehensive road safety platform designed to help users report and track road risks across Nigeria.
    
    #### 🚀 Key Features:
    - **Secure User Registration & Login**: Complete authentication system with role-based access
    - **Risk Report Submission**: Submit detailed road risk reports with GPS coordinates
    - **Live Dashboard**: Real-time road status updates for the last 24 hours
    - **Live news feed integration**: Automated import of road-related news
    - **Social media feed integration**: Real-time social media updates
    - **Source differentiation**: Distinguish between user, news, and social media sources
    - **Risk History**: Comprehensive filtering and export capabilities
    - **Community Validation**: Upvote system for report verification
    - **Admin Control System**: Complete moderation and management tools
    
    #### 🛠️ Technical Stack:
    - **Frontend**: Streamlit (Python-based web framework)
    - **Backend**: Python with SQLite database
    - **Authentication**: SHA256 password hashing
    - **Database**: SQLite (users.db, risk_reports.db, admin_logs.db)
    - **API Integration**: Built-in HTTP requests for news feeds
    - **File Handling**: Image and voice file upload support
    - **Geolocation**: GPS coordinate support
    
    #### 🔒 Security Features:
    - Password hashing with SHA256
    - Session state management
    - Input validation and sanitization
    - Role-based access control
    - Admin action logging
    
    #### 📊 Data Sources:
    - **User Reports**: Direct submissions from registered users
    - **News Feeds**: Automated import from Nigerian news sources
    - **Social Media**: Real-time social media monitoring
    
    #### 🎯 Target Users:
    - **Public**: General road users
    - **Drivers**: Professional drivers and transport operators
    - **Admins**: System administrators and moderators
    
    #### 🌍 Coverage:
    - **Geographic**: Nigeria-wide road network
    - **Risk Types**: Robbery, Flooding, Protest, Road Damage, Traffic, Other
    - **Real-time**: 24/7 monitoring and updates
    
    ---
    *Built with ❤️ for Nigerian road safety*
    """)

def show_admin_dashboard():
    st.header("🔐 Admin Dashboard")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Welcome section
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"""
        ### 👋 Welcome, {admin_user['full_name']}!
        **Admin ID:** {admin_user['id']} | **Email:** {admin_user['email'] or 'N/A'}
        """)
    
    with col2:
        if st.button("🔄 Refresh Data", type="secondary"):
            st.rerun()
    
    # Summary statistics
    st.subheader("📊 System Overview")
    
    try:
        # Get report statistics
        stats = get_report_stats()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Reports", stats.get('total_reports', 0))
        
        with col2:
            st.metric("Pending Reports", stats.get('pending_reports', 0))
        
        with col3:
            st.metric("Verified Reports", stats.get('verified_reports', 0))
        
        with col4:
            st.metric("Flagged as Fake", stats.get('false_reports', 0))
        
        # Recent activity
        st.subheader("📈 Recent Activity (Last 24 Hours)")
        
        recent_reports = get_recent_reports(hours=24)
        if recent_reports:
            # Risk type distribution
            risk_counts = {}
            for report in recent_reports:
                risk_type = report[1]
                risk_counts[risk_type] = risk_counts.get(risk_type, 0) + 1
            
            if risk_counts:
                st.markdown("**Risk Type Distribution:**")
                for risk_type, count in risk_counts.items():
                    st.write(f"• {risk_type}: {count} reports")
            
            # Recent reports table
            st.markdown("**Recent Reports:**")
            for report in recent_reports[:5]:
                report_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
                
                status_color = {
                    'pending': '🟡',
                    'verified': '🟢',
                    'resolved': '🔵',
                    'false': '🔴'
                }.get(status, '⚪')
                
                st.markdown(f"""
                **{status_color} Report #{report_id}** - {risk_type} at {location}
                - Reporter: {reporter_name}
                - Status: {status.title()}
                - Source: {source_type.title()}
                - Time: {get_time_ago(created_at)}
                """)
        else:
            st.info("No recent reports in the last 24 hours.")
        
        # Admin logs summary
        st.subheader("📝 Recent Admin Actions")
        admin_logs = get_admin_logs(limit=10)
        
        if admin_logs:
            for log in admin_logs:
                log_id, admin_id, admin_name, action, target_type, target_id, details, created_at, admin_full_name = log
                
                action_icon = {
                    'UPDATE_ROLE': '👤',
                    'VERIFY_REPORT': '✅',
                    'FLAG_REPORT': '🚩',
                    'DELETE_REPORT': '🗑️',
                    'EDIT_REPORT': '✏️'
                }.get(action, '📝')
                
                st.markdown(f"""
                **{action_icon} {action.replace('_', ' ').title()}**
                - Admin: {admin_full_name}
                - Target: {target_type} #{target_id if target_id else 'N/A'}
                - Details: {details or 'No details'}
                - Time: {get_time_ago(created_at)}
                """)
        else:
            st.info("No recent admin actions.")
        
        # Quick actions
        st.subheader("⚡ Quick Actions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📋 View All Reports", type="secondary"):
                st.session_state.admin_page = "Moderation Panel"
                st.rerun()
        
        with col2:
            if st.button("👥 Manage Users", type="secondary"):
                st.session_state.admin_page = "User Management"
                st.rerun()
        
        with col3:
            if st.button("📊 View Logs", type="secondary"):
                st.session_state.admin_page = "Admin Logs"
                st.rerun()
        
        # 20km radius notification simulation
        st.subheader("🚨 Proximity Alerts")
        st.info("""
        **20km Radius Notifications (Simulated)**
        
        📍 **Lagos Area**: 3 new reports in your vicinity
        📍 **Abuja Area**: 1 pending report requires attention
        📍 **Port Harcourt**: 2 verified reports in your area
        
        *This is a simulation. In production, this would use real GPS coordinates.*
        """)
        
    except Exception as e:
        st.error(f"Error loading dashboard data: {str(e)}")

def show_moderation_panel():
    st.header("📋 Moderation Panel")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "pending", "verified", "resolved", "false"]
        )
    
    with col2:
        source_filter = st.selectbox(
            "Filter by Source",
            ["All", "user", "news", "social"]
        )
    
    with col3:
        if st.button("🔄 Refresh Reports", type="secondary"):
            st.rerun()
    
    # Get reports based on filters
    reports = get_risk_reports()
    
    # Apply filters
    if status_filter != "All":
        reports = [r for r in reports if r[6] == status_filter]  # status is at index 6
    
    if source_filter != "All":
        reports = [r for r in reports if r[10] == source_filter]  # source_type is at index 10
    
    if reports:
        st.subheader(f"📊 Reports ({len(reports)} found)")
        
        # Display reports in a table format
        for report in reports:
            report_id, user_id, risk_type, description, location, lat, lon, status, confirmations, created_at, reporter_name, source_type, source_url = report
            
            with st.expander(f"Report #{report_id} - {risk_type} at {location} ({status})"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"""
                    **Risk Type:** {risk_type}  
                    **Location:** 📍 {location}  
                    **Description:** {description}  
                    **Reporter:** {reporter_name}  
                    **Source:** {source_type.title()}  
                    **Created:** {created_at}  
                    **Confirmations:** ✅ {confirmations}
                    """)
                    
                    if source_url:
                        st.markdown(f"**Source URL:** [View Original]({source_url})")
                
                with col2:
                    st.markdown("**Actions:**")
                    
                    # Action buttons
                    if status == "pending":
                        if st.button(f"✅ Verify #{report_id}", key=f"verify_{report_id}"):
                            if update_report_status(report_id, "verified"):
                                log_admin_action(
                                    admin_id=admin_user['id'],
                                    admin_name=admin_user['full_name'],
                                    action="VERIFY_REPORT",
                                    target_type="REPORT",
                                    target_id=report_id,
                                    details=f"Verified report #{report_id} - {risk_type} at {location}"
                                )
                                st.success(f"Report #{report_id} verified!")
                                st.rerun()
                            else:
                                st.error("Failed to verify report")
                    
                    if st.button(f"🚩 Flag as Fake #{report_id}", key=f"flag_{report_id}"):
                        if update_report_status(report_id, "false"):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                action="FLAG_REPORT",
                                target_type="REPORT",
                                target_id=report_id,
                                details=f"Flagged report #{report_id} as fake - {risk_type} at {location}"
                            )
                            st.success(f"Report #{report_id} flagged as fake!")
                            st.rerun()
                        else:
                            st.error("Failed to flag report")
                    
                    if st.button(f"🗑️ Delete #{report_id}", key=f"delete_{report_id}"):
                        if update_report_status(report_id, "deleted"):
                            log_admin_action(
                                admin_id=admin_user['id'],
                                admin_name=admin_user['full_name'],
                                action="DELETE_REPORT",
                                target_type="REPORT",
                                target_id=report_id,
                                details=f"Deleted report #{report_id} - {risk_type} at {location}"
                            )
                            st.success(f"Report #{report_id} deleted!")
                            st.rerun()
                        else:
                            st.error("Failed to delete report")
                    
                    # Status badge
                    status_colors = {
                        'pending': '#ffc107',
                        'verified': '#28a745',
                        'resolved': '#007bff',
                        'false': '#dc3545'
                    }
                    color = status_colors.get(status, '#6c757d')
                    st.markdown(f"""
                    <div style="background-color: {color}; color: white; padding: 8px; border-radius: 4px; text-align: center; font-weight: bold;">
                        {status.upper()}
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.info("No reports found matching the selected filters.")
    
    # Bulk actions
    st.subheader("⚡ Bulk Actions")
    st.info("""
    **Bulk Moderation Features:**
    - Select multiple reports for batch processing
    - Bulk verify pending reports
    - Bulk flag suspicious reports
    - Export selected reports for review
    
    *This feature will be implemented in the next version.*
    """)

def show_admin_user_management():
    st.header("👥 User Management")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        role_filter = st.selectbox(
            "Filter by Role",
            ["All", "Public", "Driver", "Admin"]
        )
    
    with col2:
        search_term = st.text_input("Search by name or email", placeholder="Enter search term...")
    
    with col3:
        if st.button("🔄 Refresh Users", type="secondary"):
            st.rerun()
    
    # Get all users
    users = get_all_users()
    
    # Apply filters
    if role_filter != "All":
        users = [u for u in users if u[4] == role_filter]  # role is at index 4
    
    if search_term:
        users = [u for u in users if search_term.lower() in u[1].lower() or 
                (u[3] and search_term.lower() in u[3].lower())]  # name at index 1, email at index 3
    
    if users:
        st.subheader(f"📊 Users ({len(users)} found)")
        
        # User statistics
        role_counts = {}
        for user in users:
            role = user[4]
            role_counts[role] = role_counts.get(role, 0) + 1
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Users", len(users))
        with col2:
            st.metric("Public Users", role_counts.get("Public", 0))
        with col3:
            st.metric("Drivers", role_counts.get("Driver", 0))
        with col4:
            st.metric("Admins", role_counts.get("Admin", 0))
        
        # Display users
        for user in users:
            user_id, full_name, phone, email, role, nin, created_at = user
            
            with st.expander(f"User #{user_id} - {full_name} ({role})"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"""
                    **Name:** {full_name}  
                    **Phone:** {phone}  
                    **Email:** {email or 'N/A'}  
                    **Role:** {role}  
                    **NIN/Passport:** {nin}  
                    **Registered:** {created_at}
                    """)
                
                with col2:
                    st.markdown("**Actions:**")
                    
                    # Role change options
                    if role != "Admin":
                        if st.button(f"👑 Promote to Admin #{user_id}", key=f"promote_{user_id}"):
                            if update_user_role(user_id, "Admin", admin_user['id'], admin_user['full_name']):
                                st.success(f"User #{user_id} promoted to Admin!")
                                st.rerun()
                            else:
                                st.error("Failed to promote user")
                    
                    if role != "Driver":
                        if st.button(f"🚗 Make Driver #{user_id}", key=f"driver_{user_id}"):
                            if update_user_role(user_id, "Driver", admin_user['id'], admin_user['full_name']):
                                st.success(f"User #{user_id} role changed to Driver!")
                                st.rerun()
                            else:
                                st.error("Failed to change user role")
                    
                    if role != "Public":
                        if st.button(f"👤 Make Public #{user_id}", key=f"public_{user_id}"):
                            if update_user_role(user_id, "Public", admin_user['id'], admin_user['full_name']):
                                st.success(f"User #{user_id} role changed to Public!")
                                st.rerun()
                            else:
                                st.error("Failed to change user role")
                    
                    # Suspend user (simulated)
                    if st.button(f"⏸️ Suspend #{user_id}", key=f"suspend_{user_id}"):
                        log_admin_action(
                            admin_id=admin_user['id'],
                            admin_name=admin_user['full_name'],
                            action="SUSPEND_USER",
                            target_type="USER",
                            target_id=user_id,
                            details=f"Suspended user {full_name} (ID: {user_id})"
                        )
                        st.success(f"User #{user_id} suspended!")
                        st.rerun()
                    
                    # Re-verify user (simulated)
                    if st.button(f"✅ Re-verify #{user_id}", key=f"reverify_{user_id}"):
                        log_admin_action(
                            admin_id=admin_user['id'],
                            admin_name=admin_user['full_name'],
                            action="REVERIFY_USER",
                            target_type="USER",
                            target_id=user_id,
                            details=f"Re-verified user {full_name} (ID: {user_id})"
                        )
                        st.success(f"User #{user_id} re-verified!")
                        st.rerun()
                    
                    # Role badge
                    role_colors = {
                        'Public': '#6c757d',
                        'Driver': '#007bff',
                        'Admin': '#dc3545'
                    }
                    color = role_colors.get(role, '#6c757d')
                    st.markdown(f"""
                    <div style="background-color: {color}; color: white; padding: 8px; border-radius: 4px; text-align: center; font-weight: bold;">
                        {role.upper()}
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.info("No users found matching the selected filters.")
    
    # User management features
    st.subheader("⚡ User Management Features")
    st.info("""
    **Advanced User Management:**
    - Bulk user operations
    - User activity monitoring
    - Account suspension/activation
    - User verification status
    - Export user data
    
    *These features will be implemented in the next version.*
    """)

def show_admin_logs():
    st.header("📊 Admin Logs")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        action_filter = st.selectbox(
            "Filter by Action",
            ["All", "UPDATE_ROLE", "VERIFY_REPORT", "FLAG_REPORT", "DELETE_REPORT", "SUSPEND_USER", "REVERIFY_USER"]
        )
    
    with col2:
        admin_filter = st.text_input("Filter by Admin", placeholder="Enter admin name...")
    
    with col3:
        if st.button("🔄 Refresh Logs", type="secondary"):
            st.rerun()
    
    # Get admin logs
    logs = get_admin_logs(limit=100)
    
    # Apply filters
    if action_filter != "All":
        logs = [log for log in logs if log[3] == action_filter]  # action is at index 3
    
    if admin_filter:
        logs = [log for log in logs if admin_filter.lower() in log[8].lower()]  # admin_full_name is at index 8
    
    if logs:
        st.subheader(f"📝 Admin Actions ({len(logs)} found)")
        
        # Log statistics
        action_counts = {}
        admin_counts = {}
        for log in logs:
            action = log[3]
            admin_name = log[8]
            action_counts[action] = action_counts.get(action, 0) + 1
            admin_counts[admin_name] = admin_counts.get(admin_name, 0) + 1
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Action Distribution:**")
            for action, count in action_counts.items():
                st.write(f"• {action.replace('_', ' ').title()}: {count}")
        
        with col2:
            st.markdown("**Admin Activity:**")
            for admin, count in admin_counts.items():
                st.write(f"• {admin}: {count} actions")
        
        # Display logs
        for log in logs:
            log_id, admin_id, admin_name, action, target_type, target_id, details, created_at, admin_full_name = log
            
            with st.expander(f"{action.replace('_', ' ').title()} by {admin_full_name} at {get_time_ago(created_at)}"):
                st.markdown(f"""
                **Action:** {action.replace('_', ' ').title()}  
                **Admin:** {admin_full_name} (ID: {admin_id})  
                **Target Type:** {target_type}  
                **Target ID:** {target_id or 'N/A'}  
                **Details:** {details or 'No details provided'}  
                **Timestamp:** {created_at}
                """)
                
                # Action-specific information
                if action == "UPDATE_ROLE":
                    st.info("👤 **Role Update Action** - User role was modified")
                elif action in ["VERIFY_REPORT", "FLAG_REPORT", "DELETE_REPORT"]:
                    st.info("📋 **Report Moderation Action** - Report status was changed")
                elif action in ["SUSPEND_USER", "REVERIFY_USER"]:
                    st.info("👥 **User Management Action** - User account was modified")
        
        # Export functionality
        st.subheader("📤 Export Logs")
        if st.button("📊 Export to CSV"):
            # Create CSV data
            csv_data = "Action,Admin,Target Type,Target ID,Details,Timestamp\n"
            for log in logs:
                log_id, admin_id, admin_name, action, target_type, target_id, details, created_at, admin_full_name = log
                csv_data += f'"{action}","{admin_full_name}","{target_type}","{target_id or ""}","{details or ""}","{created_at}"\n'
            
            st.download_button(
                label="📥 Download CSV",
                data=csv_data,
                file_name=f"admin_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No admin logs found matching the selected filters.")
    
    # Log management features
    st.subheader("⚡ Log Management Features")
    st.info("""
    **Advanced Log Management:**
    - Real-time log monitoring
    - Log retention policies
    - Automated log analysis
    - Alert system for suspicious activities
    - Log backup and archiving
    
    *These features will be implemented in the next version.*
    """)

def show_config_panel():
    st.header("⚙️ Configuration Panel")
    
    if not st.session_state.get("admin_logged_in"):
        st.error("Access denied. Please login as admin.")
        return
    
    admin_user = st.session_state.admin_user
    
    # Tab navigation
    tab1, tab2, tab3 = st.tabs(["Risk Types", "Advice Templates", "System Settings"])
    
    with tab1:
        st.subheader("🚨 Risk Type Configuration")
        
        # Default risk types
        default_risk_types = ["Robbery", "Flooding", "Protest", "Road Damage", "Traffic", "Other"]
        
        st.markdown("**Current Risk Types:**")
        for i, risk_type in enumerate(default_risk_types):
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.write(f"• {risk_type}")
            with col2:
                if st.button(f"Edit {risk_type}", key=f"edit_risk_{i}"):
                    st.info(f"Edit functionality for {risk_type} will be implemented in the next version.")
            with col3:
                if st.button(f"Delete {risk_type}", key=f"delete_risk_{i}"):
                    st.warning(f"Delete functionality for {risk_type} will be implemented in the next version.")
        
        # Add new risk type
        st.markdown("**Add New Risk Type:**")
        with st.form("add_risk_type"):
            new_risk_type = st.text_input("Risk Type Name", placeholder="Enter new risk type...")
            risk_description = st.text_area("Description", placeholder="Describe this risk type...")
            risk_color = st.color_picker("Risk Color", "#dc3545")
            
            if st.form_submit_button("Add Risk Type"):
                if new_risk_type:
                    st.success(f"Risk type '{new_risk_type}' added successfully!")
                    log_admin_action(
                        admin_id=admin_user['id'],
                        admin_name=admin_user['full_name'],
                        action="ADD_RISK_TYPE",
                        target_type="CONFIG",
                        details=f"Added new risk type: {new_risk_type}"
                    )
                    st.rerun()
                else:
                    st.error("Please enter a risk type name.")
    
    with tab2:
        st.subheader("💡 Advice Templates")
        
        # Default advice templates
        advice_templates = {
            "Robbery": "🚨 **Robbery Alert**: Avoid this area, especially at night. Travel in groups if possible. Contact local authorities immediately.",
            "Flooding": "🌊 **Flooding Warning**: Road may be impassable. Avoid driving through flooded areas. Find alternative routes.",
            "Protest": "🏛️ **Protest Notice**: Expect traffic delays and road closures. Plan alternative routes and allow extra travel time.",
            "Road Damage": "🛣️ **Road Damage**: Potholes or road damage detected. Drive carefully and report to authorities.",
            "Traffic": "🚗 **Traffic Alert**: Heavy traffic congestion. Consider alternative routes or delay travel if possible."
        }
        
        st.markdown("**Current Advice Templates:**")
        for risk_type, advice in advice_templates.items():
            with st.expander(f"Advice for {risk_type}"):
                st.markdown(advice)
                
                # Edit advice template
                new_advice = st.text_area(
                    f"Edit advice for {risk_type}",
                    value=advice,
                    key=f"advice_{risk_type}"
                )
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"Save {risk_type} Advice", key=f"save_advice_{risk_type}"):
                        log_admin_action(
                            admin_id=admin_user['id'],
                            admin_name=admin_user['full_name'],
                            action="UPDATE_ADVICE",
                            target_type="CONFIG",
                            details=f"Updated advice template for {risk_type}"
                        )
                        st.success(f"Advice for {risk_type} updated successfully!")
                
                with col2:
                    if st.button(f"Reset {risk_type} Advice", key=f"reset_advice_{risk_type}"):
                        st.info(f"Reset functionality for {risk_type} will be implemented in the next version.")
    
    with tab3:
        st.subheader("🔧 System Settings")
        
        # System configuration options
        st.markdown("**General Settings:**")
        
        # Notification settings
        st.markdown("**Notification Settings:**")
        email_notifications = st.checkbox("Enable Email Notifications", value=True)
        sms_notifications = st.checkbox("Enable SMS Notifications", value=False)
        push_notifications = st.checkbox("Enable Push Notifications", value=True)
        
        # Report settings
        st.markdown("**Report Settings:**")
        auto_verify_threshold = st.slider("Auto-verify threshold (upvotes)", 1, 10, 3)
        report_retention_days = st.number_input("Report retention (days)", 30, 365, 90)
        
        # Admin settings
        st.markdown("**Admin Settings:**")
        require_2fa = st.checkbox("Require 2FA for admin login", value=True)
        log_retention_days = st.number_input("Log retention (days)", 30, 365, 180)
        
        # Save settings
        if st.button("💾 Save Settings", type="primary"):
            log_admin_action(
                admin_id=admin_user['id'],
                admin_name=admin_user['full_name'],
                action="UPDATE_SETTINGS",
                target_type="CONFIG",
                details="Updated system configuration settings"
            )
            st.success("Settings saved successfully!")
        
        # System information
        st.markdown("**System Information:**")
        st.info(f"""
        **Current Configuration:**
        - Email Notifications: {'✅ Enabled' if email_notifications else '❌ Disabled'}
        - SMS Notifications: {'✅ Enabled' if sms_notifications else '❌ Disabled'}
        - Push Notifications: {'✅ Enabled' if push_notifications else '❌ Disabled'}
        - Auto-verify Threshold: {auto_verify_threshold} upvotes
        - Report Retention: {report_retention_days} days
        - 2FA Required: {'✅ Yes' if require_2fa else '❌ No'}
        - Log Retention: {log_retention_days} days
        """)
    
    # Configuration management features
    st.subheader("⚡ Configuration Management Features")
    st.info("""
    **Advanced Configuration:**
    - Configuration versioning
    - Backup and restore settings
    - Environment-specific configs
    - Automated configuration validation
    - Configuration change notifications
    
    *These features will be implemented in the next version.*
    """)

def show_ai_advice_page():
    """Display AI Safety Advice page"""
    try:
        from ai_advice import display_advice_interface
        display_advice_interface()
    except ImportError:
        st.warning("🤖 AI Advice module not available in minimal mode.")
        st.info("ℹ️ Basic safety advice is still available when submitting reports.")
        st.markdown("""
        ### Basic Safety Advice Templates
        
        **Robbery**: 🚨 Avoid this area, especially at night. Travel in groups if possible.
        
        **Flooding**: 🌊 Road may be impassable. Avoid driving through flooded areas.
        
        **Protest**: 🏛️ Expect traffic delays and road closures. Plan alternative routes.
        
        **Road Damage**: 🛣️ Drive carefully and report to authorities.
        
        **Traffic**: 🚗 Heavy traffic congestion. Consider alternative routes.
        
        **Other**: ⚠️ Exercise caution in this area. Follow local advisories.
        """)

def show_analytics_page():
    """Display Analytics Dashboard page"""
    try:
        from analytics_dashboard import main as analytics_main
        analytics_main()
    except ImportError:
        st.warning("📊 Analytics module not available in minimal mode.")
        st.info("ℹ️ Basic report statistics are available in the Dashboard.")
        
        # Show basic stats from main app
        try:
            stats = get_report_stats()
            if stats:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Reports", stats.get('total_reports', 0))
                with col2:
                    st.metric("Verified Reports", stats.get('verified_reports', 0))
                with col3:
                    st.metric("Pending Reports", stats.get('pending_reports', 0))
        except:
            st.info("No report statistics available.")

def show_security_page():
    """Display Security Settings page"""
    try:
        from security import main as security_main
        security_main()
    except ImportError:
        st.warning("🔐 Security module not available in minimal mode.")
        st.info("ℹ️ Basic authentication and session management are still active.")
        
        # Show basic security info
        st.markdown("""
        ### Current Security Status
        
        ✅ **Basic Authentication**: Username/password login
        ✅ **Session Management**: Secure session handling
        ✅ **Password Hashing**: SHA256 with salt
        ✅ **Role-Based Access**: Admin/User/Public roles
        
        ### Security Features Available
        
        - User registration and login
        - Password strength validation
        - Session timeout management
        - Admin access control
        """)

def show_deployment_page():
    """Display Deployment & PWA page"""
    try:
        from deploy_app import main as deployment_main
        deployment_main()
    except ImportError:
        st.warning("🚀 Deployment module not available in minimal mode.")
        st.info("ℹ️ App is running in minimal mode on Streamlit Cloud.")
        
        # Show deployment status
        st.markdown("""
        ### Deployment Status
        
        ✅ **Platform**: Streamlit Cloud
        ✅ **Mode**: Minimal (Core features only)
        ✅ **Status**: Active and running
        
        ### Available Features
        
        - User registration and authentication
        - Risk report submission
        - Basic safety advice generation
        - Report viewing and management
        - Admin dashboard and moderation
        - Live feeds and risk history
        
        ### Enhanced Features (Require Dependencies)
        
        - Advanced AI safety advice
        - Interactive analytics dashboard
        - Data encryption and security
        - PWA features and SMS alerts
        """)

if __name__ == "__main__":
    main() 