# 🚗 Nigerian Road Risk Reporting App - Streamlit Version

A secure, user-friendly registration system for the Nigerian Road Risk Reporting application built with Streamlit.

## 🎯 Features

### Core Registration Features
- **Multi-role Support**: Admin, Driver, and Public user registration
- **Nigerian Identity Validation**: NIN (11 digits) and International Passport support
- **Phone Number Validation**: Nigerian phone number format validation
- **Optional Email**: Email validation when provided
- **File Upload**: ID document upload (PDF/JPEG/PNG) with 5MB limit
- **Password Security**: bcrypt hashing for secure password storage

### User Interface
- **Modern Streamlit UI**: Clean, responsive interface
- **Multi-page Navigation**: Registration, User Management, and About pages
- **Real-time Validation**: Instant feedback on form inputs
- **File Upload Interface**: Drag-and-drop file upload
- **User Management Dashboard**: View and manage registered users

## 🛠 Tech Stack

- **Frontend & Backend**: Streamlit (Python)
- **Database**: SQLite
- **Security**: bcrypt for password hashing
- **File Handling**: Streamlit file uploader
- **Validation**: Custom Python validation functions

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements_streamlit.txt
   ```

3. **Run the Streamlit application**:
   ```bash
   streamlit run streamlit_app.py
   ```

4. **Access the application**:
   - The app will automatically open in your browser
   - Default URL: `http://localhost:8501`

## 📁 Project Structure

```
V8_Road_Status_Report/
├── streamlit_app.py           # Main Streamlit application
├── requirements_streamlit.txt # Streamlit dependencies
├── README_Streamlit.md       # This file
├── uploads/                  # File upload directory (auto-created)
└── users.db                 # SQLite database (auto-created)
```

## 🎨 User Interface

### Registration Page
- Clean form layout with two columns
- Real-time validation feedback
- File upload interface
- Success/error messages with animations

### User Management Page
- Table view of all registered users
- User verification functionality
- Status indicators (pending/verified)
- Action buttons for each user

### About Page
- Application information
- Feature overview
- Technical stack details

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

## 🔄 Registration Flow

1. **Form Submission**: User fills out registration form
2. **Validation**: Real-time client-side validation
3. **File Upload**: ID document upload (optional)
4. **Database Storage**: User data stored with hashed password
5. **Verification**: Admin can verify user identity
6. **Account Activation**: User account marked as verified

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    phone_number TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    role TEXT NOT NULL,
    nin_or_passport TEXT UNIQUE NOT NULL,
    official_authority TEXT,
    id_file_path TEXT,
    password_hash TEXT NOT NULL,
    registration_status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1
);
```

## 🚀 Streamlit Cloud Deployment

### Prerequisites for Streamlit Cloud
1. **GitHub Repository**: Your code must be in a GitHub repository
2. **Requirements File**: `requirements_streamlit.txt` must be in the root directory
3. **Main File**: `streamlit_app.py` must be the main application file

### Deployment Steps

1. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Add Streamlit version"
   git push origin main
   ```

2. **Deploy on Streamlit Cloud**:
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Sign in with GitHub
   - Click "New app"
   - Select your repository
   - Set the main file path to: `streamlit_app.py`
   - Click "Deploy"

### Streamlit Cloud Configuration

Create a `.streamlit/config.toml` file for custom configuration:

```toml
[theme]
primaryColor = "#667eea"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
font = "sans serif"

[server]
maxUploadSize = 5
```

## 🧪 Testing

### Manual Testing
1. **Basic Registration**: Test with valid data
2. **Validation Testing**: Test with invalid inputs
3. **File Upload**: Test with various file types and sizes
4. **Role Testing**: Test Admin role with authority field
5. **User Management**: Test user verification process

### Test Data Examples

**Valid NIN**: `12345678901`
**Valid Phone**: `+2348012345678` or `08012345678`
**Valid Email**: `user@example.com`
**Valid Passport**: `A1234567`

## 🔧 Customization

### Adding New Roles
1. Update the role options in the selectbox
2. Add role-specific validation logic
3. Update the database schema if needed
4. Add role-specific UI elements

### Modifying Validation Rules
1. Update validation functions in the code
2. Modify error messages
3. Update the UI to reflect new validation rules

### File Upload Customization
1. Modify allowed file types in the file_uploader
2. Update file size limits
3. Change upload directory structure

## 🚀 Production Considerations

### Security
1. **Environment Variables**: Use Streamlit secrets for sensitive data
2. **Database**: Consider using PostgreSQL for production
3. **File Storage**: Use cloud storage (AWS S3, etc.) for file uploads
4. **HTTPS**: Streamlit Cloud provides HTTPS by default

### Performance
1. **Database Optimization**: Add indexes for frequently queried fields
2. **File Handling**: Implement file compression and optimization
3. **Caching**: Use Streamlit caching for expensive operations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support or questions:
- Check the documentation above
- Review the code comments for implementation details
- Test with the provided examples
- Contact the development team

## 🔮 Future Enhancements

- [ ] Email verification system
- [ ] SMS OTP verification
- [ ] Advanced admin dashboard
- [ ] Data export functionality
- [ ] Advanced file validation (OCR)
- [ ] Integration with Nigerian government APIs
- [ ] Multi-language support
- [ ] Advanced security features (2FA, rate limiting) 