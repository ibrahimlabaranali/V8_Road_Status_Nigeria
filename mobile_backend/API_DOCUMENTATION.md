# 📱 Nigerian Road Risk Reporter - Mobile Backend API Documentation

## 🚀 Overview

This document provides comprehensive documentation for the Nigerian Road Risk Reporter Mobile Backend API, designed specifically for Android mobile application development.

**Base URL**: `https://your-domain.com/api/v1`  
**API Version**: v1  
**Authentication**: JWT Bearer Token  

## 🔐 Authentication

### JWT Token Flow

1. **Register/Login** → Get access token
2. **Include token** in Authorization header: `Bearer <token>`
3. **Token expires** after 30 minutes
4. **Refresh token** to get new access token

### Headers Required
```http
Authorization: Bearer <your_jwt_token>
Content-Type: application/json
```

## 📋 API Endpoints

### 🔑 Authentication Endpoints

#### 1. User Registration
```http
POST /auth/register
```

**Request Body:**
```json
{
  "username": "string (3-50 chars)",
  "email": "valid_email@domain.com",
  "password": "string (min 8 chars)",
  "full_name": "string",
  "phone": "+2348012345678",
  "state": "string",
  "lga": "string"
}
```

**Response (201):**
```json
{
  "id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "full_name": "John Doe",
  "phone": "+2348012345678",
  "state": "Lagos",
  "lga": "Victoria Island",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### 2. User Login
```http
POST /auth/login
```

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "full_name": "John Doe"
  }
}
```

#### 3. Refresh Token
```http
POST /auth/refresh
```

**Headers:** `Authorization: Bearer <current_token>`

**Response (200):**
```json
{
  "access_token": "new_jwt_token_here",
  "token_type": "bearer",
  "expires_in": 1800
}
```

#### 4. Forgot Password
```http
POST /auth/forgot-password
```

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

#### 5. Reset Password
```http
POST /auth/reset-password
```

**Request Body:**
```json
{
  "token": "reset_token_from_email",
  "new_password": "new_password_123"
}
```

### 📝 Report Management

#### 1. Create Risk Report
```http
POST /reports
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "title": "Large Pothole on Main Street",
  "description": "Deep pothole causing traffic delays",
  "location": "Main Street, Victoria Island, Lagos",
  "latitude": 6.4281,
  "longitude": 3.4219,
  "risk_level": "high",
  "road_condition": "poor",
  "traffic_impact": "high",
  "category": "pothole"
}
```

**Response (201):**
```json
{
  "id": 123,
  "title": "Large Pothole on Main Street",
  "description": "Deep pothole causing traffic delays",
  "location": "Main Street, Victoria Island, Lagos",
  "latitude": 6.4281,
  "longitude": 3.4219,
  "risk_level": "high",
  "road_condition": "poor",
  "traffic_impact": "high",
  "category": "pothole",
  "status": "pending",
  "user_id": 1,
  "username": "john_doe",
  "created_at": "2024-01-15T10:30:00Z",
  "upvotes": 0,
  "downvotes": 0
}
```

#### 2. Get Reports List
```http
GET /reports?skip=0&limit=20&category=pothole&status=pending
```

**Query Parameters:**
- `skip`: Number of records to skip (pagination)
- `limit`: Maximum number of records to return
- `category`: Filter by category
- `status`: Filter by status
- `risk_level`: Filter by risk level

#### 3. Get Specific Report
```http
GET /reports/{report_id}
```

#### 4. Update Report
```http
PUT /reports/{report_id}
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:** (Partial updates supported)
```json
{
  "title": "Updated Title",
  "description": "Updated description"
}
```

#### 5. Delete Report
```http
DELETE /reports/{report_id}
```

**Headers:** `Authorization: Bearer <token>`

#### 6. Vote on Report
```http
POST /reports/{report_id}/vote?vote_type=upvote
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `vote_type`: `upvote` or `downvote`

#### 7. Get Nearby Reports
```http
GET /reports/nearby?latitude=6.4281&longitude=3.4219&radius_km=10
```

**Query Parameters:**
- `latitude`: User's latitude
- `longitude`: User's longitude
- `radius_km`: Search radius in kilometers

#### 8. Search Reports
```http
GET /reports/search?query=pothole&category=road_hazard&risk_level=high&limit=20
```

**Query Parameters:**
- `query`: Search text
- `category`: Filter by category
- `risk_level`: Filter by risk level
- `state`: Filter by state
- `limit`: Maximum results

### 📸 File Upload

#### Upload Image
```http
POST /upload/image
```

**Headers:** `Authorization: Bearer <token>`

**Request:** `multipart/form-data`
- `file`: Image file (JPEG, PNG, WebP, max 10MB)

**Response (200):**
```json
{
  "success": true,
  "file_url": "/uploads/john_doe_1705312200_abc123.jpg",
  "filename": "john_doe_1705312200_abc123.jpg",
  "size": 245760,
  "content_type": "image/jpeg"
}
```

### 🔔 Push Notifications

#### Register Device
```http
POST /notifications/register
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "device_token": "fcm_device_token_here",
  "platform": "android"
}
```

#### Unregister Device
```http
POST /notifications/unregister
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "device_token": "fcm_device_token_here"
}
```

### 🔄 Offline Sync

#### Get Offline Data
```http
GET /sync/offline?last_sync=2024-01-15T10:00:00Z
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `last_sync`: ISO timestamp of last sync

#### Upload Offline Data
```http
POST /sync/upload
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
[
  {
    "title": "Offline Report",
    "description": "Created while offline",
    "location": "Offline Location",
    "latitude": 6.4281,
    "longitude": 3.4219,
    "risk_level": "medium",
    "road_condition": "fair",
    "traffic_impact": "low",
    "category": "other"
  }
]
```

### 🚨 Emergency Alerts

#### Create Emergency Alert
```http
POST /alerts/emergency
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "title": "Road Blocked",
  "description": "Major accident blocking entire road",
  "location": "Lekki Expressway",
  "latitude": 6.4281,
  "longitude": 3.4219,
  "severity": "critical"
}
```

**Severity Levels:**
- `low`: 24 hours
- `medium`: 12 hours
- `high`: 6 hours
- `critical`: 3 hours
- `emergency`: 1 hour

#### Get Active Alerts
```http
GET /alerts/active?latitude=6.4281&longitude=3.4219&radius_km=50
```

### 👥 Community Features

#### Submit Feedback
```http
POST /community/feedback
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "feedback_type": "feature",
  "title": "Dark Mode Request",
  "description": "Please add dark mode to the app"
}
```

**Feedback Types:**
- `bug`: Bug report
- `feature`: Feature request
- `improvement`: Improvement suggestion
- `other`: Other feedback

#### Get Community Leaderboard
```http
GET /community/leaderboard?period=month
```

**Period Options:**
- `week`: Last 7 days
- `month`: Last 30 days
- `year`: Last 365 days
- `all`: All time

### 📊 Analytics

#### User Analytics
```http
GET /analytics/user/{user_id}
```

**Headers:** `Authorization: Bearer <token>`

#### Trending Analytics
```http
GET /analytics/trends
```

### 📤 Export Reports

#### Export User Reports
```http
GET /reports/export?format=json
```

**Headers:** `Authorization: Bearer <token>`

**Format Options:**
- `json`: JSON format
- `csv`: CSV format

### ⚙️ Configuration

#### Mobile App Config
```http
GET /config/mobile
```

**Response:**
```json
{
  "app_version": "1.0.0",
  "api_version": "v1",
  "features": {
    "image_upload": true,
    "push_notifications": true,
    "offline_sync": true,
    "location_services": true,
    "real_time_updates": true
  },
  "limits": {
    "max_image_size_mb": 10,
    "max_reports_per_day": 50,
    "rate_limit_per_minute": 100
  },
  "supported_image_types": ["image/jpeg", "image/png", "image/webp"],
  "update_required": false,
  "maintenance_mode": false
}
```

#### App Status
```http
GET /app/status
```

### 🏥 Health Check
```http
GET /health
```

## 📱 Mobile App Integration Examples

### Android (Kotlin) - Retrofit Example

```kotlin
// API Interface
interface RoadStatusApi {
    @POST("auth/login")
    suspend fun login(@Body loginRequest: LoginRequest): LoginResponse
    
    @GET("reports")
    suspend fun getReports(
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 20
    ): List<Report>
    
    @POST("reports")
    suspend fun createReport(
        @Header("Authorization") token: String,
        @Body report: CreateReportRequest
    ): Report
    
    @Multipart
    @POST("upload/image")
    suspend fun uploadImage(
        @Header("Authorization") token: String,
        @Part file: MultipartBody.Part
    ): UploadResponse
}

// Usage
class ReportRepository(private val api: RoadStatusApi) {
    suspend fun login(username: String, password: String): LoginResponse {
        return api.login(LoginRequest(username, password))
    }
    
    suspend fun getReports(skip: Int = 0, limit: Int = 20): List<Report> {
        return api.getReports(skip, limit)
    }
    
    suspend fun createReport(token: String, report: CreateReportRequest): Report {
        return api.createReport("Bearer $token", report)
    }
    
    suspend fun uploadImage(token: String, imageFile: File): UploadResponse {
        val requestFile = RequestBody.create("image/*".toMediaTypeOrNull(), imageFile)
        val body = MultipartBody.Part.createFormData("file", imageFile.name, requestFile)
        return api.uploadImage("Bearer $token", body)
    }
}
```

### iOS (Swift) - URLSession Example

```swift
class RoadStatusAPI {
    private let baseURL = "https://your-domain.com/api/v1"
    private var authToken: String?
    
    func login(username: String, password: String) async throws -> LoginResponse {
        let url = URL(string: "\(baseURL)/auth/login")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let loginData = LoginRequest(username: username, password: password)
        request.httpBody = try JSONEncoder().encode(loginData)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        let response = try JSONDecoder().decode(LoginResponse.self, from: data)
        
        self.authToken = response.accessToken
        return response
    }
    
    func getReports(skip: Int = 0, limit: Int = 20) async throws -> [Report] {
        let url = URL(string: "\(baseURL)/reports?skip=\(skip)&limit=\(limit)")!
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode([Report].self, from: data)
    }
    
    func createReport(report: CreateReportRequest) async throws -> Report {
        guard let token = authToken else {
            throw APIError.unauthorized
        }
        
        let url = URL(string: "\(baseURL)/reports")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        request.httpBody = try JSONEncoder().encode(report)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(Report.self, from: data)
    }
}
```

## 🔒 Security Features

### Rate Limiting
- **Limit**: 100 requests per minute per IP
- **Response**: 429 Too Many Requests when exceeded
- **Headers**: `Retry-After` indicates when to retry

### Input Validation
- **SQL Injection**: Prevented through parameterized queries
- **XSS**: Input sanitization and validation
- **File Upload**: Type and size validation

### Authentication
- **JWT Tokens**: Secure, stateless authentication
- **Password Hashing**: bcrypt with salt
- **Token Expiration**: 30 minutes for security

## 📊 Error Handling

### Standard Error Response
```json
{
  "error": true,
  "message": "Error description",
  "status_code": 400,
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/v1/reports"
}
```

### Common HTTP Status Codes
- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `422`: Validation Error
- `429`: Too Many Requests
- `500`: Internal Server Error

## 🚀 Best Practices

### 1. Token Management
- Store tokens securely (Android Keystore, iOS Keychain)
- Implement automatic token refresh
- Handle token expiration gracefully

### 2. Offline Support
- Cache essential data locally
- Queue offline actions
- Sync when connection restored

### 3. Error Handling
- Implement retry logic for network errors
- Show user-friendly error messages
- Log errors for debugging

### 4. Performance
- Implement pagination for large datasets
- Use image compression before upload
- Cache frequently accessed data

### 5. User Experience
- Show loading states during API calls
- Implement pull-to-refresh
- Provide offline indicators

## 🔧 Development Setup

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Run tests
pytest test_api.py -v
```

### Docker Development
```bash
# Build and run with Docker Compose
docker-compose up --build

# Run tests in container
docker-compose exec mobile-backend pytest test_api.py -v
```

## 📞 Support

For API support and questions:
- **Documentation**: `/docs` (Swagger UI)
- **ReDoc**: `/redoc` (Alternative documentation)
- **GitHub**: Repository issues
- **Email**: support@your-domain.com

---

**Last Updated**: January 2024  
**API Version**: v1.0.0  
**Maintainer**: Nigerian Road Risk Reporter Team 