#!/usr/bin/env python3
"""
Database Setup Module for Nigerian Road Risk Reporter Admin System
Shared database initialization and utility functions
"""

import sqlite3
import hashlib
import streamlit as st
from datetime import datetime
import os

def init_databases():
    """Initialize all required databases for the admin system"""
    try:
        # Create db directory if it doesn't exist
        os.makedirs('db', exist_ok=True)
        
        # Initialize users database
        init_users_db()
        
        # Initialize risk reports database
        init_risk_reports_db()
        
        # Initialize admin logs database
        init_admin_logs_db()
        
        # Initialize upvotes database
        init_upvotes_db()
        
        return True
    except Exception as e:
        st.error(f"Database initialization error: {str(e)}")
        return False

def init_users_db():
    """Initialize users database"""
    try:
        conn = sqlite3.connect('db/users.db')
        cursor = conn.cursor()
        
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
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Users database error: {str(e)}")
        return False

def init_risk_reports_db():
    """Initialize risk reports database"""
    try:
        conn = sqlite3.connect('db/risk_reports.db')
        cursor = conn.cursor()
        
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
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Risk reports database error: {str(e)}")
        return False

def init_admin_logs_db():
    """Initialize admin logs database"""
    try:
        conn = sqlite3.connect('db/admin_logs.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                admin_name TEXT NOT NULL,
                admin_email TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Admin logs database error: {str(e)}")
        return False

def init_upvotes_db():
    """Initialize upvotes database for community validation"""
    try:
        conn = sqlite3.connect('db/upvotes.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS upvotes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                report_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, report_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Upvotes database error: {str(e)}")
        return False

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == hashed

def log_admin_action(admin_id: int, admin_name: str, admin_email: str, action: str, target_type: str, target_id: int = None, details: str = None):
    """Log admin action to admin_logs.db"""
    try:
        conn = sqlite3.connect('db/admin_logs.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO admin_logs (admin_id, admin_name, admin_email, action, target_type, target_id, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (admin_id, admin_name, admin_email, action, target_type, target_id, details))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to log admin action: {str(e)}")
        return False

def get_time_ago(timestamp_str: str) -> str:
    """Convert timestamp to 'time ago' format"""
    try:
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        diff = now - timestamp
        
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
    except:
        return "Unknown time"

# Initialize databases when module is imported
init_databases() 