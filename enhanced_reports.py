#!/usr/bin/env python3
"""
Enhanced Reports Module - Multi-source road reporting system
Supports user reports, social media, government sources, and news media
Includes verification status and live report capture
"""

import sqlite3
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import streamlit as st
import time
import re

# News API configuration (you'll need to get an API key)
NEWS_API_KEY = st.secrets.get("NEWS_API_KEY", "")  # Add to Streamlit secrets
BBC_RSS_URL = "https://feeds.bbci.co.uk/news/rss.xml"
NIGERIA_NEWS_KEYWORDS = [
    "flooding", "banditry", "road", "highway", "accident", "traffic", 
    "construction", "repair", "bridge", "pothole", "security", "travel"
]

class EnhancedReportSystem:
    def __init__(self):
        self.db_path = 'enhanced_reports.db'
        self.init_database()
    
    def init_database(self):
        """Initialize enhanced reports database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Enhanced reports table with multiple sources
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS enhanced_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    location TEXT NOT NULL,
                    state TEXT NOT NULL,
                    local_government TEXT,
                    road_name TEXT,
                    latitude REAL,
                    longitude REAL,
                    source_type TEXT NOT NULL,  -- 'user', 'social_media', 'government', 'news_media'
                    source_name TEXT NOT NULL,  -- specific source (e.g., 'BBC', 'Twitter', 'FRSC')
                    source_url TEXT,
                    source_verified BOOLEAN DEFAULT FALSE,
                    user_confirmations INTEGER DEFAULT 0,
                    admin_verified BOOLEAN DEFAULT FALSE,
                    verified_by_admin_id INTEGER,
                    verification_date TIMESTAMP,
                    risk_type TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Report verifications table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS report_verifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER NOT NULL,
                    user_id INTEGER,
                    user_type TEXT NOT NULL,  -- 'user', 'admin'
                    verification_type TEXT NOT NULL,  -- 'confirm', 'dispute', 'resolve'
                    comment TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (report_id) REFERENCES enhanced_reports (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Live feeds table for external sources
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS live_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_type TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    url TEXT,
                    published_date TIMESTAMP,
                    processed BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Database initialization error: {e}")
            return False
    
    def add_user_report(self, report_data: Dict) -> bool:
        """Add a user-submitted report"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO enhanced_reports (
                    title, description, location, state, local_government, road_name,
                    latitude, longitude, source_type, source_name, risk_type, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report_data.get('title', ''),
                report_data.get('description', ''),
                report_data.get('location', ''),
                report_data.get('state', ''),
                report_data.get('local_government', ''),
                report_data.get('road_name', ''),
                report_data.get('latitude'),
                report_data.get('longitude'),
                'user',
                report_data.get('user_name', 'Anonymous User'),
                report_data.get('risk_type', 'general'),
                report_data.get('severity', 'medium')
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding user report: {e}")
            return False
    
    def add_news_report(self, news_data: Dict) -> bool:
        """Add a news media report"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO enhanced_reports (
                    title, description, location, state, source_type, source_name,
                    source_url, source_verified, risk_type, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                news_data.get('title', ''),
                news_data.get('description', ''),
                news_data.get('location', ''),
                news_data.get('state', ''),
                'news_media',
                news_data.get('source_name', ''),
                news_data.get('url', ''),
                True,  # News sources are pre-verified
                news_data.get('risk_type', 'general'),
                news_data.get('severity', 'medium')
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding news report: {e}")
            return False
    
    def add_government_report(self, gov_data: Dict) -> bool:
        """Add a government source report"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO enhanced_reports (
                    title, description, location, state, local_government, road_name,
                    source_type, source_name, source_url, source_verified, admin_verified,
                    risk_type, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                gov_data.get('title', ''),
                gov_data.get('description', ''),
                gov_data.get('location', ''),
                gov_data.get('state', ''),
                gov_data.get('local_government', ''),
                gov_data.get('road_name', ''),
                'government',
                gov_data.get('source_name', ''),
                gov_data.get('url', ''),
                True,  # Government sources are pre-verified
                True,  # Government sources are admin-verified
                gov_data.get('risk_type', 'general'),
                gov_data.get('severity', 'medium')
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding government report: {e}")
            return False
    
    def verify_report(self, report_id: int, user_id: int, user_type: str, 
                     verification_type: str, comment: str = "") -> bool:
        """Verify or dispute a report"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Add verification record
            cursor.execute('''
                INSERT INTO report_verifications (
                    report_id, user_id, user_type, verification_type, comment
                ) VALUES (?, ?, ?, ?, ?)
            ''', (report_id, user_id, user_type, verification_type, comment))
            
            # Update report based on verification type
            if verification_type == 'confirm':
                cursor.execute('''
                    UPDATE enhanced_reports 
                    SET user_confirmations = user_confirmations + 1
                    WHERE id = ?
                ''', (report_id,))
            elif verification_type == 'dispute':
                cursor.execute('''
                    UPDATE enhanced_reports 
                    SET status = 'disputed'
                    WHERE id = ?
                ''', (report_id,))
            elif verification_type == 'resolve':
                cursor.execute('''
                    UPDATE enhanced_reports 
                    SET status = 'resolved'
                    WHERE id = ?
                ''', (report_id,))
            elif verification_type == 'false_report':
                cursor.execute('''
                    UPDATE enhanced_reports 
                    SET status = 'false_report', admin_verified = TRUE, verified_by_admin_id = ?, verification_date = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user_id, report_id))
            
            # If admin verifies, mark as admin_verified
            if user_type == 'admin' and verification_type == 'confirm':
                cursor.execute('''
                    UPDATE enhanced_reports 
                    SET admin_verified = TRUE, verified_by_admin_id = ?, verification_date = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user_id, report_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error verifying report: {e}")
            return False
    
    def mark_false_report(self, report_id: int, admin_id: int, reason: str = "") -> bool:
        """Mark a report as false (admin only)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Add verification record for false report
            cursor.execute('''
                INSERT INTO report_verifications (
                    report_id, user_id, user_type, verification_type, comment
                ) VALUES (?, ?, ?, ?, ?)
            ''', (report_id, admin_id, 'admin', 'false_report', reason))
            
            # Update report status to false_report
            cursor.execute('''
                UPDATE enhanced_reports 
                SET status = 'false_report', admin_verified = TRUE, verified_by_admin_id = ?, verification_date = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (admin_id, report_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error marking false report: {e}")
            return False
    
    def get_reports(self, source_type: str = None, state: str = None, 
                   hours: int = 24, verified_only: bool = False) -> List[Dict]:
        """Get reports with filters"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = '''
                SELECT * FROM enhanced_reports 
                WHERE created_at >= datetime('now', '-{} hours')
            '''.format(hours)
            
            params = []
            
            if source_type:
                query += " AND source_type = ?"
                params.append(source_type)
            
            if state:
                query += " AND state = ?"
                params.append(state)
            
            if verified_only:
                query += " AND (source_verified = TRUE OR admin_verified = TRUE)"
            
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, params)
            reports = []
            
            for row in cursor.fetchall():
                reports.append({
                    'id': row[0],
                    'title': row[1],
                    'description': row[2],
                    'location': row[3],
                    'state': row[4],
                    'local_government': row[5],
                    'road_name': row[6],
                    'latitude': row[7],
                    'longitude': row[8],
                    'source_type': row[9],
                    'source_name': row[10],
                    'source_url': row[11],
                    'source_verified': row[12],
                    'user_confirmations': row[13],
                    'admin_verified': row[14],
                    'verified_by_admin_id': row[15],
                    'verification_date': row[16],
                    'risk_type': row[17],
                    'severity': row[18],
                    'status': row[19],
                    'created_at': row[20],
                    'updated_at': row[21]
                })
            
            conn.close()
            return reports
        except Exception as e:
            print(f"Error getting reports: {e}")
            return []
    
    def get_report_statistics(self) -> Dict:
        """Get comprehensive report statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            stats = {}
            
            # Total reports by source type
            cursor.execute('''
                SELECT source_type, COUNT(*) FROM enhanced_reports 
                WHERE created_at >= datetime('now', '-24 hours')
                GROUP BY source_type
            ''')
            stats['by_source_24h'] = dict(cursor.fetchall())
            
            # Total reports by state
            cursor.execute('''
                SELECT state, COUNT(*) FROM enhanced_reports 
                WHERE created_at >= datetime('now', '-24 hours')
                GROUP BY state
                ORDER BY COUNT(*) DESC
                LIMIT 10
            ''')
            stats['by_state_24h'] = dict(cursor.fetchall())
            
            # Verification statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN source_verified = TRUE OR admin_verified = TRUE THEN 1 ELSE 0 END) as verified,
                    SUM(CASE WHEN admin_verified = TRUE THEN 1 ELSE 0 END) as admin_verified
                FROM enhanced_reports 
                WHERE created_at >= datetime('now', '-24 hours')
            ''')
            row = cursor.fetchone()
            stats['verification_stats'] = {
                'total': row[0],
                'verified': row[1],
                'admin_verified': row[2]
            }
            
            conn.close()
            return stats
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}
    
    def capture_live_reports(self) -> List[Dict]:
        """Capture live reports from external sources"""
        captured_reports = []
        
        # Capture BBC news (simulated - in real implementation, you'd use RSS/API)
        bbc_reports = self._capture_bbc_news()
        captured_reports.extend(bbc_reports)
        
        # Capture government alerts (simulated)
        gov_reports = self._capture_government_alerts()
        captured_reports.extend(gov_reports)
        
        # Capture social media trends (simulated)
        social_reports = self._capture_social_media()
        captured_reports.extend(social_reports)
        
        return captured_reports
    
    def _capture_bbc_news(self) -> List[Dict]:
        """Capture BBC news related to Nigerian roads"""
        # Simulated BBC news capture
        bbc_reports = [
            {
                'title': 'Flooding in Lagos: Major roads affected',
                'description': 'Heavy rainfall has caused flooding in several parts of Lagos, affecting major roads including the Lagos-Ibadan Expressway.',
                'location': 'Lagos',
                'state': 'Lagos',
                'source_type': 'news_media',
                'source_name': 'BBC News',
                'source_url': 'https://www.bbc.com/news/nigeria',
                'risk_type': 'weather',
                'severity': 'high'
            },
            {
                'title': 'Banditry alert: Travel advisory for Zamfara roads',
                'description': 'Security forces have issued travel advisories for major roads in Zamfara state due to increased bandit activity.',
                'location': 'Zamfara',
                'state': 'Zamfara',
                'source_type': 'news_media',
                'source_name': 'BBC News',
                'source_url': 'https://www.bbc.com/news/nigeria',
                'risk_type': 'security',
                'severity': 'high'
            }
        ]
        
        # Add to database
        for report in bbc_reports:
            self.add_news_report(report)
        
        return bbc_reports
    
    def _capture_government_alerts(self) -> List[Dict]:
        """Capture government road alerts"""
        # Simulated government alerts
        gov_reports = [
            {
                'title': 'FRSC Alert: Road construction on Abuja-Kaduna Highway',
                'description': 'Federal Road Safety Corps alerts motorists of ongoing construction work on Abuja-Kaduna Highway. Expect delays.',
                'location': 'Abuja-Kaduna Highway',
                'state': 'Kaduna',
                'source_type': 'government',
                'source_name': 'FRSC',
                'source_url': 'https://frsc.gov.ng',
                'risk_type': 'infrastructure',
                'severity': 'medium'
            },
            {
                'title': 'NEMA Warning: Flash floods expected in Rivers State',
                'description': 'National Emergency Management Agency warns of potential flash floods affecting major roads in Rivers State.',
                'location': 'Rivers State',
                'state': 'Rivers',
                'source_type': 'government',
                'source_name': 'NEMA',
                'source_url': 'https://nema.gov.ng',
                'risk_type': 'weather',
                'severity': 'high'
            }
        ]
        
        # Add to database
        for report in gov_reports:
            self.add_government_report(report)
        
        return gov_reports
    
    def _capture_social_media(self) -> List[Dict]:
        """Capture social media reports (simulated)"""
        # Simulated social media reports
        social_reports = [
            {
                'title': 'Traffic gridlock on Third Mainland Bridge',
                'description': 'Multiple users report severe traffic congestion on Third Mainland Bridge due to vehicle breakdown.',
                'location': 'Third Mainland Bridge',
                'state': 'Lagos',
                'source_type': 'social_media',
                'source_name': 'Twitter',
                'source_url': 'https://twitter.com',
                'risk_type': 'traffic',
                'severity': 'medium'
            }
        ]
        
        # Add to database
        for report in social_reports:
            self.add_news_report(report)  # Treat as news for now
        
        return social_reports

# Initialize the enhanced report system
enhanced_reports_system = EnhancedReportSystem() 