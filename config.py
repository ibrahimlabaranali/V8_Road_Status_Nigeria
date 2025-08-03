"""
Configuration settings for the Nigerian Road Risk Reporting App
"""

import os
from pathlib import Path

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")

# Security Settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# File Upload Settings
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
UPLOAD_DIR = Path("uploads")
ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png'}

# Server Settings
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))
DEBUG = os.getenv("DEBUG", "True").lower() == "true"

# Validation Patterns
NIGERIAN_PHONE_PATTERN = r'^(\+234|0)[789][01]\d{8}$'
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
NIN_PATTERN = r'^\d{11}$'

# Valid Roles
VALID_ROLES = ['Admin', 'Driver', 'Public']

# Registration Status
REGISTRATION_STATUSES = ['pending', 'verified', 'rejected'] 