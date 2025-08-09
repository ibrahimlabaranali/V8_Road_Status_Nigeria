#!/usr/bin/env python3
"""
Enhanced Test suite for Mobile Backend API
Comprehensive testing of all endpoints and functionality
"""

import pytest
import asyncio
import json
import tempfile
import os
from fastapi.testclient import TestClient
from fastapi import status
from main import app
from config import settings

# Test client
client = TestClient(app)

# Test data
TEST_USER = {
    "username": "testuser",
    "email": "test@example.com",
    "password": "testpassword123",
    "full_name": "Test User",
    "phone": "+2348012345678",
    "state": "Lagos",
    "lga": "Victoria Island"
}

TEST_REPORT = {
    "title": "Test Road Hazard",
    "description": "This is a test report for testing purposes",
    "location": "Test Location, Lagos",
    "latitude": 6.4281,
    "longitude": 3.4219,
    "risk_level": "medium",
    "road_condition": "poor",
    "traffic_impact": "low",
    "category": "pothole"
}

class TestAuthentication:
    """Test authentication endpoints"""
    
    def test_register_user_success(self):
        """Test successful user registration"""
        response = client.post("/api/v1/auth/register", json=TEST_USER)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["username"] == TEST_USER["username"]
        assert data["email"] == TEST_USER["email"]
        assert "password" not in data
    
    def test_login_user_success(self):
        """Test successful user login"""
        response = client.post("/api/v1/auth/login", json={
            "username": TEST_USER["username"],
            "password": TEST_USER["password"]
        })
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = client.post("/api/v1/auth/login", json={
            "username": TEST_USER["username"],
            "password": "wrongpassword"
        })
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

class TestReports:
    """Test report management endpoints"""
    
    def test_create_report_success(self, auth_token):
        """Test successful report creation"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.post("/api/v1/reports", json=TEST_REPORT, headers=headers)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["title"] == TEST_REPORT["title"]
        assert data["status"] == "pending"
    
    def test_get_reports(self):
        """Test getting reports"""
        response = client.get("/api/v1/reports")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_report_by_id(self, auth_token):
        """Test getting a specific report"""
        # First create a report
        headers = {"Authorization": f"Bearer {auth_token}"}
        create_response = client.post("/api/v1/reports", json=TEST_REPORT, headers=headers)
        report_id = create_response.json()["id"]
        
        # Then get it
        response = client.get(f"/api/v1/reports/{report_id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == report_id

class TestFileUpload:
    """Test file upload functionality"""
    
    def test_upload_image_success(self, auth_token):
        """Test successful image upload"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        # Create a test image file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_file:
            tmp_file.write(b"fake image data")
            tmp_file.flush()
            
            with open(tmp_file.name, "rb") as f:
                files = {"file": ("test.jpg", f, "image/jpeg")}
                response = client.post("/api/v1/upload/image", files=files, headers=headers)
            
            os.unlink(tmp_file.name)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert "file_url" in data
    
    def test_upload_invalid_file_type(self, auth_token):
        """Test upload with invalid file type"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp_file:
            tmp_file.write(b"text file content")
            tmp_file.flush()
            
            with open(tmp_file.name, "rb") as f:
                files = {"file": ("test.txt", f, "text/plain")}
                response = client.post("/api/v1/upload/image", files=files, headers=headers)
            
            os.unlink(tmp_file.name)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST

class TestPushNotifications:
    """Test push notification endpoints"""
    
    def test_register_device_success(self, auth_token):
        """Test successful device registration"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        data = {
            "device_token": "test_device_token_123",
            "platform": "android"
        }
        response = client.post("/api/v1/notifications/register", data=data, headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
    
    def test_unregister_device_success(self, auth_token):
        """Test successful device unregistration"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        data = {"device_token": "test_device_token_123"}
        response = client.post("/api/v1/notifications/unregister", data=data, headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True

class TestOfflineSync:
    """Test offline sync functionality"""
    
    def test_get_offline_sync_data(self, auth_token):
        """Test getting offline sync data"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.get("/api/v1/sync/offline", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert "reports" in data
    
    def test_upload_offline_data(self, auth_token):
        """Test uploading offline data"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        offline_reports = [TEST_REPORT]
        response = client.post("/api/v1/sync/upload", json=offline_reports, headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True

class TestEmergencyAlerts:
    """Test emergency alert functionality"""
    
    def test_create_emergency_alert(self, auth_token):
        """Test creating emergency alert"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        alert_data = {
            "title": "Test Emergency",
            "description": "Test emergency alert",
            "location": "Test Location",
            "latitude": 6.4281,
            "longitude": 3.4219,
            "severity": "high"
        }
        response = client.post("/api/v1/alerts/emergency", data=alert_data, headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert "alert_id" in data
    
    def test_get_active_alerts(self):
        """Test getting active emergency alerts"""
        response = client.get("/api/v1/alerts/active")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert "alerts" in data

class TestCommunityFeatures:
    """Test community features"""
    
    def test_submit_feedback(self, auth_token):
        """Test submitting community feedback"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        feedback_data = {
            "feedback_type": "feature",
            "title": "Test Feedback",
            "description": "This is test feedback"
        }
        response = client.post("/api/v1/community/feedback", data=feedback_data, headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
    
    def test_get_community_leaderboard(self):
        """Test getting community leaderboard"""
        response = client.get("/api/v1/community/leaderboard")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert "leaderboard" in data

class TestAnalytics:
    """Test analytics endpoints"""
    
    def test_get_user_analytics(self, auth_token):
        """Test getting user analytics"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.get("/api/v1/analytics/user/1", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
    
    def test_get_trending_analytics(self):
        """Test getting trending analytics"""
        response = client.get("/api/v1/analytics/trends")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert "trending_categories" in data

class TestSearchAndExport:
    """Test search and export functionality"""
    
    def test_search_reports(self):
        """Test searching reports"""
        response = client.get("/api/v1/reports/search?query=test")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert "results" in data
    
    def test_export_reports_json(self, auth_token):
        """Test exporting reports as JSON"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.get("/api/v1/reports/export?format=json", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert data["format"] == "json"
    
    def test_export_reports_csv(self, auth_token):
        """Test exporting reports as CSV"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.get("/api/v1/reports/export?format=csv", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] == True
        assert data["format"] == "csv"

class TestMobileConfig:
    """Test mobile app configuration"""
    
    def test_get_mobile_config(self):
        """Test getting mobile app configuration"""
        response = client.get("/api/v1/config/mobile")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "app_version" in data
        assert "features" in data
        assert "limits" in data
    
    def test_get_app_status(self):
        """Test getting app status"""
        response = client.get("/api/v1/app/status")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "app_status" in data
        assert "database_status" in data

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limiting(self):
        """Test that rate limiting is working"""
        # Make many requests quickly
        responses = []
        for _ in range(105):  # More than the limit
            response = client.get("/api/v1/health")
            responses.append(response)
        
        # Check if any were rate limited
        rate_limited = any(r.status_code == 429 for r in responses)
        assert rate_limited, "Rate limiting should be enforced"

class TestErrorHandling:
    """Test error handling"""
    
    def test_404_error(self):
        """Test 404 error handling"""
        response = client.get("/api/v1/nonexistent")
        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "error" in data
        assert "message" in data
    
    def test_validation_error(self):
        """Test validation error handling"""
        invalid_user = {"username": "a"}  # Too short
        response = client.post("/api/v1/auth/register", json=invalid_user)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

# Fixtures
@pytest.fixture
def auth_token():
    """Get authentication token for tests"""
    # Register user if not exists
    try:
        client.post("/api/v1/auth/register", json=TEST_USER)
    except:
        pass
    
    # Login to get token
    response = client.post("/api/v1/auth/login", json={
        "username": TEST_USER["username"],
        "password": TEST_USER["password"]
    })
    
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        return "test_token"

# Main test runner
if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 