#!/usr/bin/env python3
"""
Configuration file for Mobile Backend API
Environment-specific settings and constants
"""

import os
from typing import Optional
from pydantic import BaseSettings

class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "Nigerian Road Risk Reporter API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Database
    DATABASE_URL: str = "db/road_status.db"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # CORS
    CORS_ORIGINS: list = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list = ["*"]
    CORS_ALLOW_HEADERS: list = ["*"]
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # File Upload
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_IMAGE_TYPES: list = ["image/jpeg", "image/png", "image/webp"]
    UPLOAD_DIR: str = "uploads/"
    
    # Email (for production)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    
    # SMS (for production)
    SMS_PROVIDER: Optional[str] = None
    SMS_API_KEY: Optional[str] = None
    
    # External APIs
    MAPS_API_KEY: Optional[str] = None
    WEATHER_API_KEY: Optional[str] = None
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Monitoring
    ENABLE_METRICS: bool = False
    METRICS_PORT: int = 9090
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Global settings instance
settings = Settings()

# Environment-specific overrides
if os.getenv("ENVIRONMENT") == "production":
    settings.DEBUG = False
    settings.CORS_ORIGINS = [
        "https://yourdomain.com",
        "https://app.yourdomain.com"
    ]
elif os.getenv("ENVIRONMENT") == "staging":
    settings.DEBUG = True
    settings.CORS_ORIGINS = [
        "https://staging.yourdomain.com",
        "http://localhost:3000"
    ]
else:  # Development
    settings.DEBUG = True
    settings.CORS_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080"
    ]

# Database configuration
DATABASE_CONFIG = {
    "url": settings.DATABASE_URL,
    "pool_size": settings.DATABASE_POOL_SIZE,
    "max_overflow": settings.DATABASE_MAX_OVERFLOW,
    "echo": settings.DEBUG
}

# Security configuration
SECURITY_CONFIG = {
    "secret_key": settings.SECRET_KEY,
    "algorithm": settings.ALGORITHM,
    "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    "refresh_token_expire_days": settings.REFRESH_TOKEN_EXPIRE_DAYS
}

# CORS configuration
CORS_CONFIG = {
    "allow_origins": settings.CORS_ORIGINS,
    "allow_credentials": settings.CORS_ALLOW_CREDENTIALS,
    "allow_methods": settings.CORS_ALLOW_METHODS,
    "allow_headers": settings.CORS_ALLOW_HEADERS
}

# Rate limiting configuration
RATE_LIMIT_CONFIG = {
    "per_minute": settings.RATE_LIMIT_PER_MINUTE,
    "per_hour": settings.RATE_LIMIT_PER_HOUR
}

# File upload configuration
UPLOAD_CONFIG = {
    "max_file_size": settings.MAX_FILE_SIZE,
    "allowed_types": settings.ALLOWED_IMAGE_TYPES,
    "upload_dir": settings.UPLOAD_DIR
} 