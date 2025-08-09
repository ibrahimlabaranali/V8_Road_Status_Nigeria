#!/usr/bin/env python3
"""
Nigerian Road Risk Reporter - Mobile Backend API
FastAPI-based REST API for Android mobile app
"""

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import uvicorn
import logging
import os
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import sqlite3
import json
import hashlib
import secrets
import re
from contextlib import contextmanager
import time
from collections import defaultdict
import asyncio
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app with versioning
app = FastAPI(
    title="Nigerian Road Risk Reporter API",
    description="Backend API for Android mobile app - Road status reporting system",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# API Version
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token bearer
security = HTTPBearer()

# Rate limiting storage
rate_limit_storage = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # 1 minute
RATE_LIMIT_MAX_REQUESTS = 100  # Max requests per window

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database configuration
DATABASE_URL = "db/road_status.db"

# File upload configuration
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Mount static files for uploaded images
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    """Rate limiting middleware"""
    client_ip = request.client.host
    current_time = time.time()
    
    # Clean old entries
    rate_limit_storage[client_ip] = [
        req_time for req_time in rate_limit_storage[client_ip]
        if current_time - req_time < RATE_LIMIT_WINDOW
    ]
    
    # Check rate limit
    if len(rate_limit_storage[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "Rate limit exceeded",
                "retry_after": RATE_LIMIT_WINDOW,
                "message": "Too many requests. Please try again later."
            }
        )
    
    # Add current request
    rate_limit_storage[client_ip].append(current_time)
    
    response = await call_next(request)
    return response

# Enhanced error handling
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Enhanced HTTP exception handler for mobile apps"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler for mobile apps"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "message": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.url.path
        }
    )

# Pydantic models for request/response
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2, max_length=100)
    phone: Optional[str] = Field(None, max_length=15)
    state: str = Field(..., max_length=50)
    lga: str = Field(..., max_length=100)

class UserLogin(BaseModel):
    username: str
    password: str

class RiskReport(BaseModel):
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=10, max_length=1000)
    location: str = Field(..., min_length=5, max_length=200)
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    risk_level: str = Field(..., pattern="^(low|medium|high|critical)$")
    road_condition: str = Field(..., pattern="^(good|fair|poor|dangerous)$")
    traffic_impact: str = Field(..., pattern="^(none|low|medium|high|severe)$")
    category: str = Field(..., pattern="^(pothole|flooding|construction|accident|other)$")
    image_url: Optional[str] = None

class ReportUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=5, max_length=200)
    description: Optional[str] = Field(None, min_length=10, max_length=1000)
    risk_level: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    road_condition: Optional[str] = Field(None, pattern="^(good|fair|poor|dangerous)$")
    traffic_impact: Optional[str] = Field(None, pattern="^(none|low|medium|high|severe)$")
    status: Optional[str] = Field(None, pattern="^(pending|verified|resolved|false)$")

class PasswordReset(BaseModel):
    email: str
    new_password: str = Field(..., min_length=8)

class UserProfile(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    phone: Optional[str] = Field(None, max_length=15)
    state: Optional[str] = Field(None, max_length=50)
    lga: Optional[str] = Field(None, max_length=100)

# Response models
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    phone: Optional[str]
    state: str
    lga: str
    is_verified: bool
    created_at: str
    last_login: Optional[str]

class ReportResponse(BaseModel):
    id: int
    title: str
    description: str
    location: str
    latitude: float
    longitude: float
    risk_level: str
    road_condition: str
    traffic_impact: str
    category: str
    status: str
    image_url: Optional[str]
    user_id: int
    username: str
    upvotes: int
    downvotes: int
    created_at: str
    updated_at: str

class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: UserResponse

class StatsResponse(BaseModel):
    total_reports: int
    pending_reports: int
    verified_reports: int
    resolved_reports: int
    false_reports: int
    total_users: int
    active_reports_24h: int

# Database utilities
@contextmanager
def get_db_connection():
    """Database connection context manager"""
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    """Initialize database tables"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                phone TEXT,
                state TEXT NOT NULL,
                lga TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                is_locked BOOLEAN DEFAULT FALSE,
                lockout_until TIMESTAMP
            )
        """)
        
        # Risk reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                location TEXT NOT NULL,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                risk_level TEXT NOT NULL,
                road_condition TEXT NOT NULL,
                traffic_impact TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                image_url TEXT,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Report votes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                vote_type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES risk_reports (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(report_id, user_id)
            )
        """)
        
        # Password reset tokens
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Admin logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES users (id)
            )
        """)
        
        conn.commit()

# Security utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return user data"""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(username: str = Depends(verify_token)):
    """Get current user from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user['is_locked'] and user['lockout_until'] and datetime.fromisoformat(user['lockout_until']) > datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked"
            )
        
        return dict(user)

# API endpoints
@app.post(f"{API_PREFIX}/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistration):
    """Register a new user"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if username or email already exists
            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", 
                         (user_data.username, user_data.email))
            if cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username or email already exists"
                )
            
            # Hash password and create user
            password_hash = get_password_hash(user_data.password)
            
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, phone, state, lga)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user_data.username, user_data.email, password_hash,
                user_data.full_name, user_data.phone, user_data.state, user_data.lga
            ))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            # Fetch created user
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            
            return UserResponse(
                id=user['id'],
                username=user['username'],
                email=user['email'],
                full_name=user['full_name'],
                phone=user['phone'],
                state=user['state'],
                lga=user['lga'],
                is_verified=user['is_verified'],
                created_at=user['created_at'],
                last_login=user['last_login']
            )
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@app.post(f"{API_PREFIX}/auth/login", response_model=AuthResponse)
async def login_user(user_data: UserLogin):
    """Authenticate user and return access token"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get user by username
            cursor.execute("SELECT * FROM users WHERE username = ?", (user_data.username,))
            user = cursor.fetchone()
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            
            # Check if account is locked
            if user['is_locked'] and user['lockout_until']:
                if datetime.fromisoformat(user['lockout_until']) > datetime.utcnow():
                    raise HTTPException(
                        status_code=status.HTTP_423_LOCKED,
                        detail="Account is temporarily locked"
                    )
                else:
                    # Unlock account
                    cursor.execute("UPDATE users SET is_locked = FALSE, lockout_until = NULL, failed_attempts = 0 WHERE id = ?", (user['id'],))
            
            # Verify password
            if not verify_password(user_data.password, user['password_hash']):
                # Increment failed attempts
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 5:
                    lockout_until = datetime.utcnow() + timedelta(minutes=30)
                    cursor.execute("UPDATE users SET failed_attempts = ?, is_locked = TRUE, lockout_until = ? WHERE id = ?", 
                                 (failed_attempts, lockout_until.isoformat(), user['id']))
                else:
                    cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed_attempts, user['id']))
                
                conn.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            
            # Reset failed attempts and update last login
            cursor.execute("UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?", 
                         (datetime.utcnow().isoformat(), user['id']))
            conn.commit()
            
            # Create access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user['username']}, expires_delta=access_token_expires
            )
            
            return AuthResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                user=UserResponse(
                    id=user['id'],
                    username=user['username'],
                    email=user['email'],
                    full_name=user['full_name'],
                    phone=user['phone'],
                    state=user['state'],
                    lga=user['lga'],
                    is_verified=user['is_verified'],
                    created_at=user['created_at'],
                    last_login=user['last_login']
                )
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@app.post(f"{API_PREFIX}/auth/refresh", response_model=AuthResponse)
async def refresh_token(current_user: dict = Depends(get_current_user)):
    """Refresh access token"""
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": current_user['username']}, expires_delta=access_token_expires
    )
    
    return AuthResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=current_user['id'],
            username=current_user['username'],
            email=current_user['email'],
            full_name=current_user['full_name'],
            phone=current_user['phone'],
            state=current_user['state'],
            lga=current_user['lga'],
            is_verified=current_user['is_verified'],
            created_at=current_user['created_at'],
            last_login=current_user['last_login']
        )
    )

@app.post(f"{API_PREFIX}/reports", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def create_risk_report(
    report_data: RiskReport,
    current_user: dict = Depends(get_current_user)
):
    """Create a new risk report"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO risk_reports (
                    title, description, location, latitude, longitude,
                    risk_level, road_condition, traffic_impact, category,
                    image_url, user_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_data.title, report_data.description, report_data.location,
                report_data.latitude, report_data.longitude, report_data.risk_level,
                report_data.road_condition, report_data.traffic_impact,
                report_data.category, report_data.image_url, current_user['id']
            ))
            
            report_id = cursor.lastrowid
            conn.commit()
            
            # Fetch created report
            cursor.execute("""
                SELECT r.*, u.username, 
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'upvote') as upvotes,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'downvote') as downvotes
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                WHERE r.id = ?
            """, (report_id,))
            
            report = cursor.fetchone()
            
            return ReportResponse(
                id=report['id'],
                title=report['title'],
                description=report['description'],
                location=report['location'],
                latitude=report['latitude'],
                longitude=report['longitude'],
                risk_level=report['risk_level'],
                road_condition=report['road_condition'],
                traffic_impact=report['traffic_impact'],
                category=report['category'],
                status=report['status'],
                image_url=report['image_url'],
                user_id=report['user_id'],
                username=report['username'],
                upvotes=report['upvotes'],
                downvotes=report['downvotes'],
                created_at=report['created_at'],
                updated_at=report['updated_at']
            )
            
    except Exception as e:
        logger.error(f"Report creation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create report"
        )

@app.get(f"{API_PREFIX}/reports", response_model=List[ReportResponse])
async def get_reports(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    category: Optional[str] = None,
    state: Optional[str] = None,
    risk_level: Optional[str] = None
):
    """Get risk reports with optional filtering"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Build query with filters
            query = """
                SELECT r.*, u.username,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'upvote') as upvotes,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'downvote') as downvotes
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                WHERE 1=1
            """
            params = []
            
            if status:
                query += " AND r.status = ?"
                params.append(status)
            if category:
                query += " AND r.category = ?"
                params.append(category)
            if state:
                query += " AND u.state = ?"
                params.append(state)
            if risk_level:
                query += " AND r.risk_level = ?"
                params.append(risk_level)
            
            query += " ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, skip])
            
            cursor.execute(query, params)
            reports = cursor.fetchall()
            
            return [
                ReportResponse(
                    id=report['id'],
                    title=report['title'],
                    description=report['description'],
                    location=report['location'],
                    latitude=report['latitude'],
                    longitude=report['longitude'],
                    risk_level=report['risk_level'],
                    road_condition=report['road_condition'],
                    traffic_impact=report['traffic_impact'],
                    category=report['category'],
                    status=report['status'],
                    image_url=report['image_url'],
                    user_id=report['user_id'],
                    username=report['username'],
                    upvotes=report['upvotes'],
                    downvotes=report['downvotes'],
                    created_at=report['created_at'],
                    updated_at=report['updated_at']
                )
                for report in reports
            ]
            
    except Exception as e:
        logger.error(f"Get reports error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch reports"
        )

@app.get(f"{API_PREFIX}/reports/{{report_id}}", response_model=ReportResponse)
async def get_report(report_id: int):
    """Get a specific risk report by ID"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT r.*, u.username,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'upvote') as upvotes,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'downvote') as downvotes
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                WHERE r.id = ?
            """, (report_id,))
            
            report = cursor.fetchone()
            
            if not report:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Report not found"
                )
            
            return ReportResponse(
                id=report['id'],
                title=report['title'],
                description=report['description'],
                location=report['location'],
                latitude=report['latitude'],
                longitude=report['longitude'],
                risk_level=report['risk_level'],
                road_condition=report['road_condition'],
                traffic_impact=report['traffic_impact'],
                category=report['category'],
                status=report['status'],
                image_url=report['image_url'],
                user_id=report['user_id'],
                username=report['username'],
                upvotes=report['upvotes'],
                downvotes=report['downvotes'],
                created_at=report['created_at'],
                updated_at=report['updated_at']
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get report error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch report"
        )

@app.put(f"{API_PREFIX}/reports/{{report_id}}", response_model=ReportResponse)
async def update_report(
    report_id: int,
    report_data: ReportUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a risk report"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if report exists and user owns it or is admin
            cursor.execute("SELECT user_id, status FROM risk_reports WHERE id = ?", (report_id,))
            report = cursor.fetchone()
            
            if not report:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Report not found"
                )
            
            if report['user_id'] != current_user['id'] and not current_user['is_admin']:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to update this report"
                )
            
            # Build update query
            update_fields = []
            params = []
            
            if report_data.title is not None:
                update_fields.append("title = ?")
                params.append(report_data.title)
            if report_data.description is not None:
                update_fields.append("description = ?")
                params.append(report_data.description)
            if report_data.risk_level is not None:
                update_fields.append("risk_level = ?")
                params.append(report_data.risk_level)
            if report_data.road_condition is not None:
                update_fields.append("road_condition = ?")
                params.append(report_data.road_condition)
            if report_data.traffic_impact is not None:
                update_fields.append("traffic_impact = ?")
                params.append(report_data.traffic_impact)
            if report_data.status is not None:
                update_fields.append("status = ?")
                params.append(report_data.status)
            
            if not update_fields:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No fields to update"
                )
            
            update_fields.append("updated_at = ?")
            params.append(datetime.utcnow().isoformat())
            params.append(report_id)
            
            cursor.execute(f"UPDATE risk_reports SET {', '.join(update_fields)} WHERE id = ?", params)
            conn.commit()
            
            # Fetch updated report
            cursor.execute("""
                SELECT r.*, u.username,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'upvote') as upvotes,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'downvote') as downvotes
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                WHERE r.id = ?
            """, (report_id,))
            
            updated_report = cursor.fetchone()
            
            return ReportResponse(
                id=updated_report['id'],
                title=updated_report['title'],
                description=updated_report['description'],
                location=updated_report['location'],
                latitude=updated_report['latitude'],
                longitude=updated_report['longitude'],
                risk_level=updated_report['risk_level'],
                road_condition=updated_report['road_condition'],
                traffic_impact=updated_report['traffic_impact'],
                category=updated_report['category'],
                status=updated_report['status'],
                image_url=updated_report['image_url'],
                user_id=updated_report['user_id'],
                username=updated_report['username'],
                upvotes=updated_report['upvotes'],
                downvotes=updated_report['downvotes'],
                created_at=updated_report['created_at'],
                updated_at=updated_report['updated_at']
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update report error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update report"
        )

@app.delete(f"{API_PREFIX}/reports/{{report_id}}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(report_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a risk report"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if report exists and user owns it or is admin
            cursor.execute("SELECT user_id FROM risk_reports WHERE id = ?", (report_id,))
            report = cursor.fetchone()
            
            if not report:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Report not found"
                )
            
            if report['user_id'] != current_user['id'] and not current_user['is_admin']:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to delete this report"
                )
            
            # Delete report votes first
            cursor.execute("DELETE FROM report_votes WHERE report_id = ?", (report_id,))
            
            # Delete report
            cursor.execute("DELETE FROM risk_reports WHERE id = ?", (report_id,))
            conn.commit()
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete report error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete report"
        )

@app.post(f"{API_PREFIX}/reports/{{report_id}}/vote")
async def vote_report(
    report_id: int,
    vote_type: str,
    current_user: dict = Depends(get_current_user)
):
    """Vote on a risk report (upvote/downvote)"""
    if vote_type not in ['upvote', 'downvote']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid vote type. Must be 'upvote' or 'downvote'"
        )
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if report exists
            cursor.execute("SELECT id FROM risk_reports WHERE id = ?", (report_id,))
            if not cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Report not found"
                )
            
            # Check if user already voted
            cursor.execute("SELECT id, vote_type FROM report_votes WHERE report_id = ? AND user_id = ?", 
                         (report_id, current_user['id']))
            existing_vote = cursor.fetchone()
            
            if existing_vote:
                if existing_vote['vote_type'] == vote_type:
                    # Remove vote if same type
                    cursor.execute("DELETE FROM report_votes WHERE id = ?", (existing_vote['id'],))
                else:
                    # Change vote type
                    cursor.execute("UPDATE report_votes SET vote_type = ? WHERE id = ?", 
                                 (vote_type, existing_vote['id']))
            else:
                # Add new vote
                cursor.execute("INSERT INTO report_votes (report_id, user_id, vote_type) VALUES (?, ?, ?)",
                             (report_id, current_user['id'], vote_type))
            
            conn.commit()
            
            return {"message": "Vote recorded successfully"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vote error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record vote"
        )

@app.get(f"{API_PREFIX}/reports/nearby")
async def get_nearby_reports(
    latitude: float,
    longitude: float,
    radius_km: float = 10.0,
    limit: int = 50
):
    """Get reports within a specified radius"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Haversine formula for distance calculation
            cursor.execute("""
                SELECT r.*, u.username,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'upvote') as upvotes,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'downvote') as downvotes,
                       (6371 * acos(cos(radians(?)) * cos(radians(latitude)) * 
                        cos(radians(longitude) - radians(?)) + sin(radians(?)) * sin(radians(latitude)))) AS distance
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                HAVING distance <= ?
                ORDER BY distance
                LIMIT ?
            """, (latitude, longitude, latitude, radius_km, limit))
            
            reports = cursor.fetchall()
            
            return [
                {
                    "id": report['id'],
                    "title": report['title'],
                    "description": report['description'],
                    "location": report['location'],
                    "latitude": report['latitude'],
                    "longitude": report['longitude'],
                    "risk_level": report['risk_level'],
                    "road_condition": report['road_condition'],
                    "traffic_impact": report['traffic_impact'],
                    "category": report['category'],
                    "status": report['status'],
                    "image_url": report['image_url'],
                    "user_id": report['user_id'],
                    "username": report['username'],
                    "upvotes": report['upvotes'],
                    "downvotes": report['downvotes'],
                    "created_at": report['created_at'],
                    "updated_at": report['updated_at'],
                    "distance_km": round(report['distance'], 2)
                }
                for report in reports
            ]
            
    except Exception as e:
        logger.error(f"Nearby reports error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch nearby reports"
        )

@app.get(f"{API_PREFIX}/stats", response_model=StatsResponse)
async def get_statistics():
    """Get application statistics"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Total reports
            cursor.execute("SELECT COUNT(*) as total FROM risk_reports")
            total_reports = cursor.fetchone()['total']
            
            # Reports by status
            cursor.execute("""
                SELECT status, COUNT(*) as count
                FROM risk_reports
                GROUP BY status
            """)
            status_counts = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Total users
            cursor.execute("SELECT COUNT(*) as total FROM users")
            total_users = cursor.fetchone()['total']
            
            # Active reports in last 24 hours
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM risk_reports
                WHERE created_at >= datetime('now', '-1 day')
            """)
            active_24h = cursor.fetchone()['count']
            
            return StatsResponse(
                total_reports=total_reports,
                pending_reports=status_counts.get('pending', 0),
                verified_reports=status_counts.get('verified', 0),
                resolved_reports=status_counts.get('resolved', 0),
                false_reports=status_counts.get('false', 0),
                total_users=total_users,
                active_reports_24h=active_24h
            )
            
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch statistics"
        )

@app.get(f"{API_PREFIX}/user/profile", response_model=UserResponse)
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return UserResponse(
        id=current_user['id'],
        username=current_user['username'],
        email=current_user['email'],
        full_name=current_user['full_name'],
        phone=current_user['phone'],
        state=current_user['state'],
        lga=current_user['lga'],
        is_verified=current_user['is_verified'],
        created_at=current_user['created_at'],
        last_login=current_user['last_login']
    )

@app.put(f"{API_PREFIX}/user/profile", response_model=UserResponse)
async def update_user_profile(
    profile_data: UserProfile,
    current_user: dict = Depends(get_current_user)
):
    """Update user profile"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            update_fields = []
            params = []
            
            if profile_data.full_name is not None:
                update_fields.append("full_name = ?")
                params.append(profile_data.full_name)
            if profile_data.phone is not None:
                update_fields.append("phone = ?")
                params.append(profile_data.phone)
            if profile_data.state is not None:
                update_fields.append("state = ?")
                params.append(profile_data.state)
            if profile_data.lga is not None:
                update_fields.append("lga = ?")
                params.append(profile_data.lga)
            
            if not update_fields:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No fields to update"
                )
            
            params.append(current_user['id'])
            cursor.execute(f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?", params)
            conn.commit()
            
            # Fetch updated user
            cursor.execute("SELECT * FROM users WHERE id = ?", (current_user['id'],))
            updated_user = cursor.fetchone()
            
            return UserResponse(
                id=updated_user['id'],
                username=updated_user['username'],
                email=updated_user['email'],
                full_name=updated_user['full_name'],
                phone=updated_user['phone'],
                state=updated_user['state'],
                lga=updated_user['lga'],
                is_verified=updated_user['is_verified'],
                created_at=updated_user['created_at'],
                last_login=updated_user['last_login']
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile update error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )

@app.post(f"{API_PREFIX}/auth/forgot-password")
async def forgot_password(email: str):
    """Send password reset token"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
            if not user:
                # Don't reveal if email exists
                return {"message": "If the email exists, a reset link has been sent"}
            
            # Generate reset token
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            # Store reset token
            cursor.execute("""
                INSERT INTO password_resets (user_id, token, expires_at)
                VALUES (?, ?, ?)
            """, (user['id'], token, expires_at.isoformat()))
            
            conn.commit()
            
            # In production, send email with reset link
            # For now, just return the token
            return {
                "message": "Password reset token generated",
                "token": token,  # Remove in production
                "expires_at": expires_at.isoformat()
            }
            
    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process password reset"
        )

@app.post(f"{API_PREFIX}/auth/reset-password")
async def reset_password(reset_data: PasswordReset):
    """Reset password using token"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find valid reset token
            cursor.execute("""
                SELECT user_id FROM password_resets
                WHERE token = ? AND expires_at > datetime('now')
                ORDER BY created_at DESC
                LIMIT 1
            """, (reset_data.email,))  # Using email as token for simplicity
            
            reset_record = cursor.fetchone()
            
            if not reset_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired reset token"
                )
            
            # Update password
            password_hash = get_password_hash(reset_data.new_password)
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                         (password_hash, reset_record['user_id']))
            
            # Delete used reset token
            cursor.execute("DELETE FROM password_resets WHERE user_id = ?", (reset_record['user_id'],))
            
            conn.commit()
            
            return {"message": "Password reset successfully"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password"
        )

@app.get(f"{API_PREFIX}/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "api_version": API_VERSION
    }

# Mobile-specific endpoints
@app.post(f"{API_PREFIX}/upload/image")
async def upload_image(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Upload image for reports"""
    try:
        # Validate file type
        if file.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file type. Only JPEG, PNG, and WebP are allowed."
            )
        
        # Validate file size
        if file.size and file.size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File too large. Maximum size is 10MB."
            )
        
        # Generate unique filename
        file_extension = file.filename.split(".")[-1] if "." in file.filename else "jpg"
        filename = f"{current_user['username']}_{int(time.time())}_{secrets.token_hex(8)}.{file_extension}"
        file_path = UPLOAD_DIR / filename
        
        # Save file
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Return file URL
        file_url = f"/uploads/{filename}"
        
        return {
            "success": True,
            "file_url": file_url,
            "filename": filename,
            "size": len(content),
            "content_type": file.content_type
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image upload error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload image"
        )

@app.post(f"{API_PREFIX}/notifications/register")
async def register_push_notification(
    device_token: str = Form(...),
    platform: str = Form(..., pattern="^(android|ios)$"),
    current_user: dict = Depends(get_current_user)
):
    """Register device for push notifications"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create notifications table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS push_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    device_token TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, device_token)
                )
            """)
            
            # Insert or update device token
            cursor.execute("""
                INSERT OR REPLACE INTO push_notifications 
                (user_id, device_token, platform, updated_at)
                VALUES (?, ?, ?, datetime('now'))
            """, (current_user['id'], device_token, platform))
            
            conn.commit()
            
            return {
                "success": True,
                "message": "Device registered for notifications",
                "device_token": device_token,
                "platform": platform
            }
            
    except Exception as e:
        logger.error(f"Push notification registration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register device for notifications"
        )

@app.post(f"{API_PREFIX}/notifications/unregister")
async def unregister_push_notification(
    device_token: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Unregister device from push notifications"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM push_notifications 
                WHERE user_id = ? AND device_token = ?
            """, (current_user['id'], device_token))
            
            conn.commit()
            
            return {
                "success": True,
                "message": "Device unregistered from notifications"
            }
            
    except Exception as e:
        logger.error(f"Push notification unregistration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unregister device"
        )

@app.get(f"{API_PREFIX}/sync/offline")
async def get_offline_sync_data(
    last_sync: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get data for offline sync"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get reports since last sync
            if last_sync:
                cursor.execute("""
                    SELECT * FROM risk_reports 
                    WHERE updated_at > ? 
                    ORDER BY updated_at DESC
                    LIMIT 100
                """, (last_sync,))
            else:
                cursor.execute("""
                    SELECT * FROM risk_reports 
                    ORDER BY updated_at DESC 
                    LIMIT 100
                """)
            
            reports = cursor.fetchall()
            
            # Get user's own reports
            cursor.execute("""
                SELECT * FROM risk_reports 
                WHERE user_id = ? 
                ORDER BY updated_at DESC
            """, (current_user['id'],))
            
            user_reports = cursor.fetchall()
            
            # Get nearby reports for user's location
            # This would need user's last known location
            # For now, return empty list
            nearby_reports = []
            
            return {
                "success": True,
                "last_sync": datetime.utcnow().isoformat(),
                "reports": reports,
                "user_reports": user_reports,
                "nearby_reports": nearby_reports,
                "total_count": len(reports)
            }
            
    except Exception as e:
        logger.error(f"Offline sync error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get offline sync data"
        )

@app.post(f"{API_PREFIX}/sync/upload")
async def upload_offline_data(
    offline_reports: List[Dict[str, Any]],
    current_user: dict = Depends(get_current_user)
):
    """Upload offline reports created while app was offline"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            uploaded_count = 0
            errors = []
            
            for report_data in offline_reports:
                try:
                    # Validate report data
                    if not all(key in report_data for key in ['title', 'description', 'location', 'latitude', 'longitude']):
                        errors.append(f"Invalid report data: {report_data.get('title', 'Unknown')}")
                        continue
                    
                    # Insert report
                    cursor.execute("""
                        INSERT INTO risk_reports (
                            title, description, location, latitude, longitude,
                            risk_level, road_condition, traffic_impact, category,
                            status, user_id, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                    """, (
                        report_data['title'],
                        report_data['description'],
                        report_data['location'],
                        report_data['latitude'],
                        report_data['longitude'],
                        report_data.get('risk_level', 'medium'),
                        report_data.get('road_condition', 'fair'),
                        report_data.get('traffic_impact', 'low'),
                        report_data.get('category', 'other'),
                        'pending',
                        current_user['id']
                    ))
                    
                    uploaded_count += 1
                    
                except Exception as e:
                    errors.append(f"Failed to upload report {report_data.get('title', 'Unknown')}: {str(e)}")
            
            conn.commit()
            
            return {
                "success": True,
                "uploaded_count": uploaded_count,
                "total_count": len(offline_reports),
                "errors": errors
            }
            
    except Exception as e:
        logger.error(f"Offline upload error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload offline data"
        )

@app.get(f"{API_PREFIX}/config/mobile")
async def get_mobile_config():
    """Get mobile app configuration"""
    return {
        "app_version": "1.0.0",
        "api_version": API_VERSION,
        "features": {
            "image_upload": True,
            "push_notifications": True,
            "offline_sync": True,
            "location_services": True,
            "real_time_updates": True
        },
        "limits": {
            "max_image_size_mb": MAX_FILE_SIZE // (1024 * 1024),
            "max_reports_per_day": 50,
            "rate_limit_per_minute": RATE_LIMIT_MAX_REQUESTS
        },
        "supported_image_types": list(ALLOWED_IMAGE_TYPES),
        "update_required": False,
        "maintenance_mode": False
    }

@app.get(f"{API_PREFIX}/reports/search")
async def search_reports(
    query: str,
    category: Optional[str] = None,
    risk_level: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 20
):
    """Search reports by text query"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Build search query
            search_sql = """
                SELECT r.*, u.username, 
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'upvote') as upvotes,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'downvote') as downvotes
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                WHERE (r.title LIKE ? OR r.description LIKE ? OR r.location LIKE ?)
            """
            
            search_params = [f"%{query}%", f"%{query}%", f"%{query}%"]
            
            if category:
                search_sql += " AND r.category = ?"
                search_params.append(category)
            
            if risk_level:
                search_sql += " AND r.risk_level = ?"
                search_params.append(risk_level)
            
            if state:
                search_sql += " AND u.state = ?"
                search_params.append(state)
            
            search_sql += " ORDER BY r.created_at DESC LIMIT ?"
            search_params.append(limit)
            
            cursor.execute(search_sql, search_params)
            reports = cursor.fetchall()
            
            return {
                "success": True,
                "query": query,
                "results": reports,
                "total_count": len(reports)
            }
            
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search reports"
        )

# Real-time updates and analytics
@app.get(f"{API_PREFIX}/reports/recent")
async def get_recent_reports(limit: int = 10):
    """Get recent reports for real-time updates"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT r.*, u.username, 
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'upvote') as upvotes,
                       (SELECT COUNT(*) FROM report_votes WHERE report_id = r.id AND vote_type = 'downvote') as downvotes
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                ORDER BY r.created_at DESC
                LIMIT ?
            """, (limit,))
            
            reports = cursor.fetchall()
            
            return {
                "success": True,
                "reports": reports,
                "total_count": len(reports),
                "last_updated": datetime.utcnow().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Recent reports error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get recent reports"
        )

@app.get(f"{API_PREFIX}/analytics/user/{{user_id}}")
async def get_user_analytics(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get analytics for a specific user (own data or admin)"""
    try:
        # Check if user is requesting their own data or is admin
        if current_user['id'] != user_id and not current_user.get('is_admin', False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get user's report statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_reports,
                    COUNT(CASE WHEN status = 'verified' THEN 1 END) as verified_reports,
                    COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_reports,
                    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_reports,
                    COUNT(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 END) as reports_this_week,
                    COUNT(CASE WHEN created_at >= datetime('now', '-30 days') THEN 1 END) as reports_this_month
                FROM risk_reports 
                WHERE user_id = ?
            """, (user_id,))
            
            report_stats = cursor.fetchone()
            
            # Get user's voting activity
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_votes,
                    COUNT(CASE WHEN vote_type = 'upvote' THEN 1 END) as upvotes_given,
                    COUNT(CASE WHEN vote_type = 'downvote' THEN 1 END) as downvotes_given
                FROM report_votes 
                WHERE user_id = ?
            """, (user_id,))
            
            voting_stats = cursor.fetchone()
            
            # Get user's top categories
            cursor.execute("""
                SELECT category, COUNT(*) as count
                FROM risk_reports 
                WHERE user_id = ?
                GROUP BY category
                ORDER BY count DESC
                LIMIT 5
            """, (user_id,))
            
            top_categories = cursor.fetchall()
            
            return {
                "success": True,
                "user_id": user_id,
                "report_statistics": report_stats,
                "voting_statistics": voting_stats,
                "top_categories": top_categories,
                "generated_at": datetime.utcnow().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User analytics error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user analytics"
        )

@app.get(f"{API_PREFIX}/analytics/trends")
async def get_trending_analytics():
    """Get trending analytics for mobile dashboard"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get trending categories
            cursor.execute("""
                SELECT category, COUNT(*) as count
                FROM risk_reports 
                WHERE created_at >= datetime('now', '-7 days')
                GROUP BY category
                ORDER BY count DESC
                LIMIT 5
            """)
            
            trending_categories = cursor.fetchall()
            
            # Get trending locations
            cursor.execute("""
                SELECT state, COUNT(*) as count
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                WHERE r.created_at >= datetime('now', '-7 days')
                GROUP BY u.state
                ORDER BY count DESC
                LIMIT 5
            """)
            
            trending_locations = cursor.fetchall()
            
            # Get risk level distribution
            cursor.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM risk_reports 
                WHERE created_at >= datetime('now', '-7 days')
                GROUP BY risk_level
                ORDER BY count DESC
            """)
            
            risk_distribution = cursor.fetchall()
            
            # Get daily report count for the last 7 days
            cursor.execute("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as count
                FROM risk_reports 
                WHERE created_at >= datetime('now', '-7 days')
                GROUP BY DATE(created_at)
                ORDER BY date
            """)
            
            daily_reports = cursor.fetchall()
            
            return {
                "success": True,
                "trending_categories": trending_categories,
                "trending_locations": trending_locations,
                "risk_distribution": risk_distribution,
                "daily_reports": daily_reports,
                "period": "7 days",
                "generated_at": datetime.utcnow().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Trending analytics error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get trending analytics"
        )

@app.post(f"{API_PREFIX}/activity/log")
async def log_user_activity(
    activity_type: str = Form(...),
    details: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    """Log user activity for analytics and debugging"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create activity log table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    activity_type TEXT NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            # Log activity
            cursor.execute("""
                INSERT INTO user_activities (user_id, activity_type, details)
                VALUES (?, ?, ?)
            """, (current_user['id'], activity_type, details))
            
            conn.commit()
            
            return {
                "success": True,
                "message": "Activity logged successfully"
            }
            
    except Exception as e:
        logger.error(f"Activity logging error: {str(e)}")
        # Don't fail the request if logging fails
        return {
            "success": False,
            "message": "Activity logging failed but request continued"
        }

@app.get(f"{API_PREFIX}/reports/export")
async def export_user_reports(
    format: str = "json",
    current_user: dict = Depends(get_current_user)
):
    """Export user's reports in various formats"""
    try:
        if format not in ["json", "csv"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported format. Use 'json' or 'csv'"
            )
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT r.*, u.username
                FROM risk_reports r
                JOIN users u ON r.user_id = u.id
                WHERE r.user_id = ?
                ORDER BY r.created_at DESC
            """, (current_user['id'],))
            
            reports = cursor.fetchall()
            
            if format == "json":
                return {
                    "success": True,
                    "format": "json",
                    "reports": reports,
                    "exported_at": datetime.utcnow().isoformat(),
                    "total_count": len(reports)
                }
            elif format == "csv":
                # Generate CSV content
                csv_content = "ID,Title,Description,Location,Latitude,Longitude,Risk Level,Road Condition,Traffic Impact,Category,Status,Created At\n"
                
                for report in reports:
                    csv_content += f"{report[0]},{report[1]},{report[2]},{report[3]},{report[4]},{report[5]},{report[6]},{report[7]},{report[8]},{report[9]},{report[10]},{report[13]}\n"
                
                return {
                    "success": True,
                    "format": "csv",
                    "content": csv_content,
                    "exported_at": datetime.utcnow().isoformat(),
                    "total_count": len(reports)
                }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export reports"
        )

# Emergency alerts and community features
@app.post(f"{API_PREFIX}/alerts/emergency")
async def create_emergency_alert(
    title: str = Form(...),
    description: str = Form(...),
    location: str = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    severity: str = Form(..., pattern="^(low|medium|high|critical|emergency)$"),
    current_user: dict = Depends(get_current_user)
):
    """Create an emergency alert for immediate attention"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create emergency alerts table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS emergency_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    location TEXT NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    severity TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            # Set expiration time based on severity
            expiration_hours = {
                "low": 24,
                "medium": 12,
                "high": 6,
                "critical": 3,
                "emergency": 1
            }
            
            expires_at = datetime.utcnow() + timedelta(hours=expiration_hours.get(severity, 24))
            
            cursor.execute("""
                INSERT INTO emergency_alerts (
                    title, description, location, latitude, longitude,
                    severity, user_id, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                title, description, location, latitude, longitude,
                severity, current_user['id'], expires_at.isoformat()
            ))
            
            alert_id = cursor.lastrowid
            conn.commit()
            
            # Log emergency alert creation
            await log_user_activity(
                "emergency_alert_created",
                f"Emergency alert '{title}' created with severity {severity}",
                current_user
            )
            
            return {
                "success": True,
                "alert_id": alert_id,
                "message": "Emergency alert created successfully",
                "expires_at": expires_at.isoformat(),
                "severity": severity
            }
            
    except Exception as e:
        logger.error(f"Emergency alert creation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create emergency alert"
        )

@app.get(f"{API_PREFIX}/alerts/active")
async def get_active_emergency_alerts(
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    radius_km: float = 50.0
):
    """Get active emergency alerts in the area"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            if latitude and longitude:
                # Get alerts within radius
                cursor.execute("""
                    SELECT a.*, u.username,
                           (6371 * acos(cos(radians(?)) * cos(radians(latitude)) * 
                            cos(radians(longitude) - radians(?)) + 
                            sin(radians(?)) * sin(radians(latitude)))) AS distance
                    FROM emergency_alerts a
                    JOIN users u ON a.user_id = u.id
                    WHERE a.is_active = TRUE 
                    AND a.expires_at > datetime('now')
                    HAVING distance <= ?
                    ORDER BY a.severity DESC, a.created_at DESC
                """, (latitude, longitude, latitude, radius_km))
            else:
                # Get all active alerts
                cursor.execute("""
                    SELECT a.*, u.username
                    FROM emergency_alerts a
                    JOIN users u ON a.user_id = u.id
                    WHERE a.is_active = TRUE 
                    AND a.expires_at > datetime('now')
                    ORDER BY a.severity DESC, a.created_at DESC
                """)
            
            alerts = cursor.fetchall()
            
            return {
                "success": True,
                "alerts": alerts,
                "total_count": len(alerts),
                "radius_km": radius_km if latitude and longitude else None
            }
            
    except Exception as e:
        logger.error(f"Get active alerts error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get emergency alerts"
        )

@app.post(f"{API_PREFIX}/community/feedback")
async def submit_feedback(
    feedback_type: str = Form(..., pattern="^(bug|feature|improvement|other)$"),
    title: str = Form(...),
    description: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Submit community feedback"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create feedback table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS community_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    feedback_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            cursor.execute("""
                INSERT INTO community_feedback (user_id, feedback_type, title, description)
                VALUES (?, ?, ?, ?)
            """, (current_user['id'], feedback_type, title, description))
            
            feedback_id = cursor.lastrowid
            conn.commit()
            
            return {
                "success": True,
                "feedback_id": feedback_id,
                "message": "Feedback submitted successfully"
            }
            
    except Exception as e:
        logger.error(f"Feedback submission error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit feedback"
        )

@app.get(f"{API_PREFIX}/community/leaderboard")
async def get_community_leaderboard(period: str = "month"):
    """Get community leaderboard"""
    try:
        if period not in ["week", "month", "year", "all"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid period. Use 'week', 'month', 'year', or 'all'"
            )
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Build time filter
            time_filter = ""
            if period == "week":
                time_filter = "AND r.created_at >= datetime('now', '-7 days')"
            elif period == "month":
                time_filter = "AND r.created_at >= datetime('now', '-30 days')"
            elif period == "year":
                time_filter = "AND r.created_at >= datetime('now', '-365 days')"
            
            cursor.execute(f"""
                SELECT 
                    u.username,
                    u.state,
                    COUNT(r.id) as reports_count,
                    COUNT(CASE WHEN r.status = 'verified' THEN 1 END) as verified_reports,
                    COUNT(CASE WHEN r.status = 'resolved' THEN 1 END) as resolved_reports,
                    (SELECT COUNT(*) FROM report_votes v WHERE v.user_id = u.id) as total_votes
                FROM users u
                LEFT JOIN risk_reports r ON u.id = r.user_id {time_filter}
                GROUP BY u.id, u.username, u.state
                HAVING reports_count > 0
                ORDER BY reports_count DESC, verified_reports DESC
                LIMIT 20
            """)
            
            leaderboard = cursor.fetchall()
            
            return {
                "success": True,
                "period": period,
                "leaderboard": leaderboard,
                "total_participants": len(leaderboard),
                "generated_at": datetime.utcnow().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Leaderboard error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get leaderboard"
        )

@app.get(f"{API_PREFIX}/app/status")
async def get_app_status():
    """Get mobile app status and maintenance info"""
    return {
        "app_status": "operational",
        "maintenance_mode": False,
        "scheduled_maintenance": None,
        "current_version": "1.0.0",
        "minimum_version": "1.0.0",
        "update_required": False,
        "server_time": datetime.utcnow().isoformat(),
        "uptime": "99.9%",
        "database_status": "healthy",
        "api_status": "healthy"
    }

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database on application startup"""
    init_database()
    logger.info("Database initialized successfully")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 