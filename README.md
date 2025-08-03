# 🔐 Nigerian Road Risk Reporting App - Registration Module

A secure, modular registration system for the Nigerian Road Risk Reporting application with role-based validation, file upload capabilities, and comprehensive security features.

## 🎯 Features

### Core Registration Features
- **Multi-role Support**: Admin, Driver, and Public user registration
- **Nigerian Identity Validation**: NIN (11 digits) and International Passport support
- **Phone Number Validation**: Nigerian phone number format validation
- **Optional Email**: Email validation when provided
- **File Upload**: ID document upload (PDF/JPEG/PNG) with 5MB limit
- **Password Security**: bcrypt hashing for secure password storage

### Security Features
- **Input Validation**: Comprehensive client and server-side validation
- **File Type Validation**: Restricted file uploads to secure formats
- **Size Limits**: 5MB maximum file size enforcement
- **Unique Constraints**: Phone, NIN/Passport, and email uniqueness validation
- **Role-based Logic**: Admin role requires additional authority verification

### User Experience
- **Modern UI**: Bootstrap 5 with responsive design
- **Real-time Validation**: Client-side form validation with instant feedback
- **Drag & Drop**: File upload with drag-and-drop support
- **Progress Indicators**: Clear status messages and loading states
- **Identity Verification**: Simulated CAPTCHA/OTP verification process

## 🛠 Tech Stack

- **Backend**: FastAPI (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML5 + Bootstrap 5 + JavaScript
- **Security**: bcrypt for password hashing
- **File Handling**: aiofiles for async file operations
- **Validation**: Pydantic models with custom validators

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the application**:
   - Open your browser and go to `http://localhost:8000`
   - The registration form will be displayed

### Alternative: Using uvicorn directly
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

## 📁 Project Structure

```
V8_Road_Status_Report/
├── app.py                 # Main FastAPI application
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── templates/
│   └── registration.html # Registration form template
├── uploads/             # File upload directory (auto-created)
└── users.db            # SQLite database (auto-created)
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the project root (optional):

```env
DATABASE_URL=sqlite:///./users.db
SECRET_KEY=your-secret-key-change-this-in-production
HOST=0.0.0.0
PORT=8000
DEBUG=True
```

### Database Configuration
The application uses SQLite by default. The database file (`users.db`) will be created automatically on first run.

## 📋 API Endpoints

### Registration Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Registration form (HTML) |
| POST | `/register` | User registration |
| POST | `/verify-identity/{user_id}` | Identity verification |
| GET | `/users` | List all users (admin) |

### Registration Form Fields

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| full_name | string | Yes | Min 2 characters |
| phone_number | string | Yes | Nigerian format |
| email | string | No | Valid email format |
| role | string | Yes | Admin/Driver/Public |
| nin_or_passport | string | Yes | 11 digits or 6-9 chars |
| official_authority | string | Admin only | Required for Admin |
| password | string | Yes | Any length |
| id_file | file | No | PDF/JPG/PNG, max 5MB |

## 🔒 Security Features

### Password Security
- Passwords are hashed using bcrypt with salt
- No plain text password storage
- Secure password verification

### Input Validation
- **Phone Numbers**: Nigerian format validation (`+234` or `0` prefix)
- **NIN**: Exactly 11 digits
- **Passport**: 6-9 characters
- **Email**: Standard email format validation
- **File Uploads**: Type and size restrictions

### File Upload Security
- **Allowed Types**: PDF, JPG, JPEG, PNG only
- **Size Limit**: Maximum 5MB per file
- **Unique Filenames**: UUID-based naming to prevent conflicts
- **Secure Storage**: Files stored in dedicated uploads directory

## 🎨 User Interface Features

### Responsive Design
- Mobile-friendly Bootstrap 5 layout
- Responsive grid system
- Touch-friendly form elements

### Interactive Elements
- **Real-time Validation**: Instant feedback on form inputs
- **Password Toggle**: Show/hide password functionality
- **File Upload**: Drag-and-drop with visual feedback
- **Role-based Fields**: Dynamic form fields based on selected role
- **Progress Indicators**: Clear status messages

### Visual Design
- Modern gradient background
- Glass-morphism card design
- Professional color scheme
- Font Awesome icons
- Smooth animations and transitions

## 🔄 Registration Flow

1. **Form Submission**: User fills out registration form
2. **Validation**: Client and server-side validation
3. **File Upload**: ID document upload (optional)
4. **Database Storage**: User data stored with hashed password
5. **Verification**: Simulated identity verification process
6. **Account Activation**: User account marked as verified

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(15) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE,
    role VARCHAR(20) NOT NULL,
    nin_or_passport VARCHAR(50) UNIQUE NOT NULL,
    official_authority VARCHAR(100),
    id_file_path VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    registration_status VARCHAR(20) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);
```

## 🧪 Testing

### Manual Testing
1. **Basic Registration**: Test with valid data
2. **Validation Testing**: Test with invalid inputs
3. **File Upload**: Test with various file types and sizes
4. **Role Testing**: Test Admin role with authority field
5. **Verification**: Test identity verification process

### Test Data Examples

**Valid NIN**: `12345678901`
**Valid Phone**: `+2348012345678` or `08012345678`
**Valid Email**: `user@example.com`
**Valid Passport**: `A1234567`

## 🔧 Customization

### Adding New Roles
1. Update `VALID_ROLES` in `config.py`
2. Add role-specific validation in `UserRegistration` model
3. Update the HTML form options
4. Add role-specific logic in the registration handler

### Modifying Validation Rules
1. Update validation patterns in `config.py`
2. Modify Pydantic validators in `app.py`
3. Update client-side validation in `registration.html`

### File Upload Customization
1. Modify `ALLOWED_EXTENSIONS` in `config.py`
2. Update `MAX_FILE_SIZE` for different limits
3. Change upload directory in `UPLOAD_DIR`

## 🚀 Deployment

### Production Considerations
1. **Change Secret Key**: Update `SECRET_KEY` in production
2. **Database**: Consider using PostgreSQL for production
3. **File Storage**: Use cloud storage (AWS S3, etc.) for file uploads
4. **HTTPS**: Enable SSL/TLS for secure communication
5. **Environment Variables**: Use proper environment variable management

### Docker Deployment
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support or questions:
- Check the documentation above
- Review the code comments for implementation details
- Test with the provided examples

## 🔮 Future Enhancements

- [ ] Email verification system
- [ ] SMS OTP verification
- [ ] Admin dashboard for user management
- [ ] Advanced file validation (OCR for ID documents)
- [ ] Integration with Nigerian government APIs
- [ ] Multi-language support
- [ ] Advanced security features (2FA, rate limiting) 