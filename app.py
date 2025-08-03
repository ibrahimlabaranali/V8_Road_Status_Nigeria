"""
Nigerian Road Risk Reporting App - Registration Module
Secure registration system with role-based validation and file upload
"""

import os
import re
import uuid
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

import bcrypt
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Boolean, Text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from pydantic import BaseModel, EmailStr, field_validator
import aiofiles

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Nigerian Road Risk Reporting App", version="1.0.0")

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# File upload settings
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Templates setup
templates = Jinja2Templates(directory="templates")

# Mount static files (only if directory exists)
# app.mount("/static", StaticFiles(directory="static"), name="static")

# Database Models
class User(Base):
    """User model for storing registration data"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100), nullable=False)
    phone_number = Column(String(15), nullable=False, unique=True)
    email = Column(String(100), nullable=True, unique=True)
    role = Column(String(20), nullable=False)  # Admin, Driver, Public
    nin_or_passport = Column(String(50), nullable=False, unique=True)
    official_authority = Column(String(100), nullable=True)  # Only for Admin role
    id_file_path = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    registration_status = Column(String(20), default="pending")  # pending, verified
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class LoginAttempt(Base):
    """Login attempt logging for audit trail"""
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_identifier = Column(String(100), nullable=False)  # email or phone
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_agent = Column(String(500), nullable=True)

class PasswordReset(Base):
    """Password reset tokens"""
    __tablename__ = "password_resets"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    token = Column(String(255), nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create database tables
Base.metadata.create_all(bind=engine)

# Pydantic models for validation
class UserRegistration(BaseModel):
    """Pydantic model for user registration validation"""
    full_name: str
    phone_number: str
    email: Optional[str] = None
    role: str
    nin_or_passport: str
    official_authority: Optional[str] = None
    password: str
    
    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v):
        if len(v.strip()) < 2:
            raise ValueError('Full name must be at least 2 characters')
        return v.strip()
    
    @field_validator('phone_number')
    @classmethod
    def validate_phone_number(cls, v):
        # Nigerian phone number format validation
        phone_pattern = r'^(\+234|0)[789][01]\d{8}$'
        if not re.match(phone_pattern, v):
            raise ValueError('Invalid Nigerian phone number format')
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, v):
                raise ValueError('Invalid email format')
        return v
    
    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        valid_roles = ['Admin', 'Driver', 'Public']
        if v not in valid_roles:
            raise ValueError(f'Role must be one of: {", ".join(valid_roles)}')
        return v
    
    @field_validator('nin_or_passport')
    @classmethod
    def validate_nin_or_passport(cls, v):
        # NIN validation (11 digits) or passport validation
        if len(v) == 11 and v.isdigit():
            # NIN format
            return v
        elif len(v) >= 6 and len(v) <= 9:
            # Passport format (basic validation)
            return v
        else:
            raise ValueError('NIN must be 11 digits or provide valid passport number')
    
    @field_validator('official_authority')
    @classmethod
    def validate_official_authority(cls, v, info):
        if info.data.get('role') == 'Admin' and not v:
            raise ValueError('Official Authority Name is required for Admin role')
        return v

class UserLogin(BaseModel):
    """Pydantic model for user login validation"""
    identifier: str  # email or phone
    password: str
    
    @field_validator('identifier')
    @classmethod
    def validate_identifier(cls, v):
        if not v.strip():
            raise ValueError('Email or phone number is required')
        return v.strip()

class PasswordResetRequest(BaseModel):
    """Pydantic model for password reset request"""
    identifier: str  # email or phone
    
    @field_validator('identifier')
    @classmethod
    def validate_identifier(cls, v):
        if not v.strip():
            raise ValueError('Email or phone number is required')
        return v.strip()

class PasswordResetConfirm(BaseModel):
    """Pydantic model for password reset confirmation"""
    token: str
    new_password: str
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def save_uploaded_file(file: UploadFile) -> str:
    """Save uploaded file and return file path"""
    # Generate unique filename
    file_extension = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = UPLOAD_DIR / unique_filename
    
    # Save file
    with open(file_path, "wb") as buffer:
        content = file.file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File size exceeds 5MB limit")
        buffer.write(content)
    
    return str(file_path)

def log_login_attempt(db: Session, identifier: str, ip_address: str, success: bool, user_agent: str = None):
    """Log login attempt for audit trail"""
    login_attempt = LoginAttempt(
        user_identifier=identifier,
        ip_address=ip_address,
        success=success,
        user_agent=user_agent
    )
    db.add(login_attempt)
    db.commit()

def generate_reset_token() -> str:
    """Generate a secure reset token"""
    return str(uuid.uuid4())

def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host if request.client else "unknown"

# Routes
@app.get("/", response_class=HTMLResponse)
async def registration_form(request: Request):
    """Serve the registration form"""
    return templates.TemplateResponse("registration.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """Serve the login form"""
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_form(request: Request):
    """Serve the forgot password form"""
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_form(request: Request, token: str):
    """Serve the password reset form"""
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user_id: int = None):
    """Serve the dashboard based on user role"""
    if not user_id:
        return RedirectResponse(url="/login")
    
    # In a real app, you'd verify the user session here
    return templates.TemplateResponse("dashboard.html", {"request": request, "user_id": user_id})

@app.post("/register")
async def register_user(
    full_name: str = Form(...),
    phone_number: str = Form(...),
    email: Optional[str] = Form(None),
    role: str = Form(...),
    nin_or_passport: str = Form(...),
    official_authority: Optional[str] = Form(None),
    password: str = Form(...),
    id_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """
    Handle user registration with validation and file upload
    """
    try:
        # Validate input data
        user_data = UserRegistration(
            full_name=full_name,
            phone_number=phone_number,
            email=email,
            role=role,
            nin_or_passport=nin_or_passport,
            official_authority=official_authority,
            password=password
        )
        
        # Check if user already exists
        existing_user = db.query(User).filter(
            (User.phone_number == phone_number) |
            (User.nin_or_passport == nin_or_passport) |
            (User.email == email and email is not None)
        ).first()
        
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists with this phone, NIN/passport, or email")
        
        # Handle file upload
        id_file_path = None
        if id_file:
            # Validate file type
            allowed_extensions = {'.pdf', '.jpg', '.jpeg', '.png'}
            file_extension = Path(id_file.filename).suffix.lower()
            if file_extension not in allowed_extensions:
                raise HTTPException(status_code=400, detail="Invalid file type. Only PDF, JPG, JPEG, PNG allowed")
            
            id_file_path = save_uploaded_file(id_file)
        
        # Create new user
        hashed_password = hash_password(password)
        new_user = User(
            full_name=user_data.full_name,
            phone_number=user_data.phone_number,
            email=user_data.email,
            role=user_data.role,
            nin_or_passport=user_data.nin_or_passport,
            official_authority=user_data.official_authority,
            id_file_path=id_file_path,
            password_hash=hashed_password,
            registration_status="pending"
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        return {
            "message": "Registration successful! Please verify your identity.",
            "user_id": new_user.id,
            "status": "pending"
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
async def login_user(
    request: Request,
    identifier: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Handle user login with validation and audit logging
    """
    try:
        # Validate input data
        login_data = UserLogin(identifier=identifier, password=password)
        
        # Get client IP and user agent
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")
        
        # Find user by email or phone
        user = db.query(User).filter(
            (User.email == login_data.identifier) | 
            (User.phone_number == login_data.identifier)
        ).first()
        
        # Log login attempt
        if user and verify_password(login_data.password, user.password_hash):
            # Successful login
            log_login_attempt(db, login_data.identifier, ip_address, True, user_agent)
            
            return {
                "message": "Login successful!",
                "user_id": user.id,
                "role": user.role,
                "redirect_url": f"/dashboard?user_id={user.id}"
            }
        else:
            # Failed login
            log_login_attempt(db, login_data.identifier, ip_address, False, user_agent)
            raise HTTPException(status_code=401, detail="Invalid email/phone or password")
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/forgot-password")
async def forgot_password(
    identifier: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Handle forgot password request
    """
    try:
        # Validate input data
        reset_data = PasswordResetRequest(identifier=identifier)
        
        # Find user by email or phone
        user = db.query(User).filter(
            (User.email == reset_data.identifier) | 
            (User.phone_number == reset_data.identifier)
        ).first()
        
        if not user:
            # Don't reveal if user exists or not for security
            return {
                "message": "If the email/phone exists, a password reset link has been sent.",
                "status": "success"
            }
        
        # Generate reset token
        token = generate_reset_token()
        expires_at = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        
        # Save reset token
        reset_record = PasswordReset(
            user_id=user.id,
            token=token,
            expires_at=expires_at
        )
        db.add(reset_record)
        db.commit()
        
        # Simulate sending email (in real app, send actual email)
        print(f"=== PASSWORD RESET EMAIL ===")
        print(f"To: {user.email or user.phone_number}")
        print(f"Subject: Password Reset Request")
        print(f"Reset Link: http://localhost:8000/reset-password?token={token}")
        print(f"Token expires at: {expires_at}")
        print(f"=============================")
        
        return {
            "message": "If the email/phone exists, a password reset link has been sent.",
            "status": "success"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/reset-password")
async def reset_password(
    token: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Handle password reset confirmation
    """
    try:
        # Validate input data
        reset_data = PasswordResetConfirm(token=token, new_password=new_password)
        
        # Find valid reset token
        reset_record = db.query(PasswordReset).filter(
            PasswordReset.token == reset_data.token,
            PasswordReset.used == False,
            PasswordReset.expires_at > datetime.utcnow()
        ).first()
        
        if not reset_record:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        
        # Get user
        user = db.query(User).filter(User.id == reset_record.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Update password
        user.password_hash = hash_password(reset_data.new_password)
        reset_record.used = True
        
        db.commit()
        
        return {
            "message": "Password reset successful! You can now login with your new password.",
            "status": "success"
        }
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/verify-identity/{user_id}")
async def verify_identity(user_id: int, db: Session = Depends(get_db)):
    """
    Simulate identity verification (CAPTCHA/OTP)
    In a real app, this would integrate with actual verification services
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Simulate verification process
    user.registration_status = "verified"
    db.commit()
    
    return {
        "message": "Identity verified successfully!",
        "user_id": user.id,
        "status": "verified"
    }

@app.get("/users")
async def list_users(db: Session = Depends(get_db)):
    """List all registered users (for admin purposes)"""
    users = db.query(User).all()
    return [
        {
            "id": user.id,
            "full_name": user.full_name,
            "phone_number": user.phone_number,
            "email": user.email,
            "role": user.role,
            "registration_status": user.registration_status,
            "created_at": user.created_at
        }
        for user in users
    ]

@app.get("/login-attempts")
async def list_login_attempts(db: Session = Depends(get_db)):
    """List login attempts for audit trail (for admin purposes)"""
    attempts = db.query(LoginAttempt).order_by(LoginAttempt.timestamp.desc()).limit(100).all()
    return [
        {
            "id": attempt.id,
            "user_identifier": attempt.user_identifier,
            "ip_address": attempt.ip_address,
            "success": attempt.success,
            "timestamp": attempt.timestamp,
            "user_agent": attempt.user_agent
        }
        for attempt in attempts
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 