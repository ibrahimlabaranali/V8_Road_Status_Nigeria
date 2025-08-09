# 🚀 Nigerian Road Risk Reporter - Mobile Backend API

A robust, scalable FastAPI-based REST API designed specifically for the Nigerian Road Risk Reporter Android mobile application. This backend provides comprehensive road status reporting, user management, and real-time data synchronization capabilities.

## 🏗️ Architecture Overview

### Technology Stack
- **Framework**: FastAPI (Python 3.8+)
- **Database**: SQLite (with PostgreSQL support for production)
- **Authentication**: JWT tokens with refresh mechanism
- **Security**: bcrypt password hashing, rate limiting, CORS protection
- **Documentation**: Auto-generated OpenAPI/Swagger docs
- **Validation**: Pydantic models with comprehensive data validation

### Key Features
- 🔐 **Secure Authentication**: JWT-based auth with account lockout protection
- 📍 **GPS Integration**: Real-time location-based reporting
- 🗺️ **Geospatial Queries**: Nearby reports with distance calculation
- 📊 **Real-time Statistics**: Live dashboard data and analytics
- 🔄 **Community Features**: Voting system and report validation
- 📱 **Mobile Optimized**: RESTful API designed for mobile consumption
- 🚀 **Scalable**: Async/await architecture for high performance

## 📋 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User authentication
- `POST /api/auth/refresh` - Token refresh
- `POST /api/auth/forgot-password` - Password reset request
- `POST /api/auth/reset-password` - Password reset

### Reports
- `POST /api/reports` - Create risk report
- `GET /api/reports` - List reports with filtering
- `GET /api/reports/{id}` - Get specific report
- `PUT /api/reports/{id}` - Update report
- `DELETE /api/reports/{id}` - Delete report
- `POST /api/reports/{id}/vote` - Vote on report
- `GET /api/reports/nearby` - Get nearby reports by location

### User Management
- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update user profile

### Analytics
- `GET /api/stats` - Application statistics
- `GET /api/health` - Health check

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/ibrahimlabaranali/V8_Road_Status_Nigeria.git
cd V8_Road_Status_Nigeria/mobile_backend
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set environment variables**
```bash
# Create .env file
cp .env.example .env

# Edit .env with your configuration
SECRET_KEY=your-super-secret-key-here
ENVIRONMENT=development
```

5. **Run the application**
```bash
# Development mode
python main.py

# Or using uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

6. **Access the API**
- API Base URL: `http://localhost:8000`
- Interactive Docs: `http://localhost:8000/docs`
- ReDoc Documentation: `http://localhost:8000/redoc`

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Application
ENVIRONMENT=development
DEBUG=true

# Security
SECRET_KEY=your-super-secret-key-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=db/road_status.db

# CORS (comma-separated)
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# External APIs
MAPS_API_KEY=your-google-maps-api-key
WEATHER_API_KEY=your-weather-api-key

# Email (for production)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

### Database Configuration

The API uses SQLite by default for development. For production, you can configure PostgreSQL:

```python
# In config.py
DATABASE_URL = "postgresql://user:password@localhost/road_status"
```

## 📱 Mobile App Integration

### Authentication Flow

1. **Register User**
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123",
  "full_name": "John Doe",
  "phone": "+2348012345678",
  "state": "Lagos",
  "lga": "Victoria Island"
}
```

2. **Login**
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "securepassword123"
}
```

3. **Use Access Token**
```http
GET /api/reports
Authorization: Bearer <access_token>
```

### Report Submission

```http
POST /api/reports
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "title": "Large Pothole on Victoria Island Road",
  "description": "Deep pothole causing traffic delays",
  "location": "Victoria Island, Lagos",
  "latitude": 6.4281,
  "longitude": 3.4219,
  "risk_level": "high",
  "road_condition": "poor",
  "traffic_impact": "medium",
  "category": "pothole"
}
```

### Nearby Reports

```http
GET /api/reports/nearby?latitude=6.4281&longitude=3.4219&radius_km=5
Authorization: Bearer <access_token>
```

## 🧪 Testing

### Run Tests
```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest

# Run with coverage
pytest --cov=main --cov-report=html
```

### Test API Endpoints
```bash
# Test health endpoint
curl http://localhost:8000/api/health

# Test registration
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"password123","full_name":"Test User","state":"Lagos","lga":"Test LGA"}'
```

## 🚀 Deployment

### Production Deployment

1. **Using Gunicorn**
```bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

2. **Using Docker**
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

3. **Environment Setup**
```bash
export ENVIRONMENT=production
export SECRET_KEY=your-production-secret-key
export DATABASE_URL=postgresql://user:pass@host/db
```

### Cloud Deployment

- **Heroku**: Use the provided `Procfile`
- **AWS**: Deploy to EC2 or use Elastic Beanstalk
- **Google Cloud**: Use Cloud Run or App Engine
- **Azure**: Use App Service or Container Instances

## 🔒 Security Features

### Authentication & Authorization
- JWT token-based authentication
- Account lockout after failed attempts
- Password complexity requirements
- Session timeout management

### Data Protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CORS configuration

### Rate Limiting
- Per-minute and per-hour limits
- IP-based throttling
- Account-based restrictions

## 📊 Monitoring & Logging

### Health Checks
- `/api/health` endpoint for load balancers
- Database connectivity monitoring
- External service status

### Logging
- Structured logging with different levels
- Request/response logging
- Error tracking and reporting

### Metrics (Optional)
- Prometheus metrics endpoint
- Performance monitoring
- Custom business metrics

## 🔄 Database Schema

### Core Tables
- `users` - User accounts and profiles
- `risk_reports` - Road risk reports
- `report_votes` - Community voting system
- `password_resets` - Password recovery tokens
- `admin_logs` - Administrative actions

### Indexes
- Geographic indexes for location queries
- User activity indexes
- Report status and category indexes

## 🛠️ Development

### Code Structure
```
mobile_backend/
├── main.py              # FastAPI application
├── config.py            # Configuration management
├── requirements.txt     # Python dependencies
├── README.md           # This file
├── tests/              # Test files
├── db/                 # Database files
└── uploads/            # File uploads
```

### Adding New Endpoints

1. **Define Pydantic models** in the models section
2. **Create endpoint function** with proper decorators
3. **Add authentication** if required
4. **Implement business logic**
5. **Add error handling**
6. **Write tests**

### Database Migrations

For schema changes, create migration scripts:

```python
# migrations/add_new_field.py
def upgrade():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE users ADD COLUMN new_field TEXT")
        conn.commit()

def downgrade():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE users DROP COLUMN new_field")
        conn.commit()
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 🆘 Support

### Documentation
- API Documentation: `/docs` (Swagger UI)
- ReDoc Documentation: `/redoc`
- This README file

### Issues
- Report bugs via GitHub Issues
- Request features via GitHub Discussions
- Check existing issues for solutions

### Community
- Join our Discord server
- Follow updates on GitHub
- Contribute to the project

## 🎯 Roadmap

### Version 1.1
- [ ] Push notifications
- [ ] Real-time chat support
- [ ] Advanced analytics dashboard
- [ ] Multi-language support

### Version 1.2
- [ ] Machine learning risk assessment
- [ ] Integration with government APIs
- [ ] Advanced reporting features
- [ ] Mobile app analytics

### Version 2.0
- [ ] Microservices architecture
- [ ] GraphQL API
- [ ] Advanced caching
- [ ] Kubernetes deployment

---

**Built with ❤️ for safer roads in Nigeria** 