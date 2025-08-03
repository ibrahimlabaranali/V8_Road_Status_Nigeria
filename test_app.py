"""
Test script for the Nigerian Road Risk Reporting App Registration Module
"""

import requests
import json
import time

# Test configuration
BASE_URL = "http://localhost:8000"

def test_registration_form():
    """Test if the registration form loads correctly"""
    print("🧪 Testing registration form...")
    try:
        response = requests.get(f"{BASE_URL}/")
        if response.status_code == 200:
            print("✅ Registration form loads successfully")
            return True
        else:
            print(f"❌ Registration form failed to load: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the app is running.")
        return False

def test_user_registration():
    """Test user registration with valid data"""
    print("\n🧪 Testing user registration...")
    
    # Test data for different roles
    test_cases = [
        {
            "name": "Public User Registration",
            "data": {
                "full_name": "John Doe",
                "phone_number": "+2348012345678",
                "email": "john.doe@example.com",
                "role": "Public",
                "nin_or_passport": "12345678901",
                "password": "securepassword123"
            }
        },
        {
            "name": "Driver Registration",
            "data": {
                "full_name": "Jane Smith",
                "phone_number": "+2348023456789",
                "email": "jane.smith@example.com",
                "role": "Driver",
                "nin_or_passport": "A1234567",
                "password": "driverpass456"
            }
        },
        {
            "name": "Admin Registration",
            "data": {
                "full_name": "Admin User",
                "phone_number": "+2348034567890",
                "email": "admin@example.com",
                "role": "Admin",
                "nin_or_passport": "98765432109",
                "official_authority": "Federal Road Safety Corps",
                "password": "adminpass789"
            }
        }
    ]
    
    results = []
    for test_case in test_cases:
        print(f"  Testing: {test_case['name']}")
        try:
            response = requests.post(f"{BASE_URL}/register", data=test_case['data'])
            if response.status_code == 200:
                result = response.json()
                print(f"    ✅ Success: {result.get('message', 'Registration successful')}")
                results.append({
                    "test": test_case['name'],
                    "success": True,
                    "user_id": result.get('user_id'),
                    "status": result.get('status')
                })
            else:
                print(f"    ❌ Failed: {response.status_code} - {response.text}")
                results.append({
                    "test": test_case['name'],
                    "success": False,
                    "error": response.text
                })
        except Exception as e:
            print(f"    ❌ Error: {str(e)}")
            results.append({
                "test": test_case['name'],
                "success": False,
                "error": str(e)
            })
    
    return results

def test_identity_verification(user_id):
    """Test identity verification process"""
    print(f"\n🧪 Testing identity verification for user {user_id}...")
    try:
        response = requests.post(f"{BASE_URL}/verify-identity/{user_id}")
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Identity verification successful: {result.get('message', 'Verified')}")
            return True
        else:
            print(f"❌ Identity verification failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error during verification: {str(e)}")
        return False

def test_list_users():
    """Test listing all users"""
    print("\n🧪 Testing user listing...")
    try:
        response = requests.get(f"{BASE_URL}/users")
        if response.status_code == 200:
            users = response.json()
            print(f"✅ Successfully retrieved {len(users)} users")
            for user in users:
                print(f"  - {user['full_name']} ({user['role']}) - {user['registration_status']}")
            return True
        else:
            print(f"❌ Failed to list users: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error listing users: {str(e)}")
        return False

def test_validation_errors():
    """Test various validation error scenarios"""
    print("\n🧪 Testing validation errors...")
    
    validation_tests = [
        {
            "name": "Invalid Phone Number",
            "data": {
                "full_name": "Test User",
                "phone_number": "12345",  # Invalid
                "email": "test@example.com",
                "role": "Public",
                "nin_or_passport": "12345678901",
                "password": "password123"
            }
        },
        {
            "name": "Invalid NIN",
            "data": {
                "full_name": "Test User",
                "phone_number": "+2348012345678",
                "email": "test@example.com",
                "role": "Public",
                "nin_or_passport": "123",  # Too short
                "password": "password123"
            }
        },
        {
            "name": "Admin without Authority",
            "data": {
                "full_name": "Test Admin",
                "phone_number": "+2348012345678",
                "email": "admin@example.com",
                "role": "Admin",
                "nin_or_passport": "12345678901",
                "password": "password123"
                # Missing official_authority
            }
        }
    ]
    
    for test in validation_tests:
        print(f"  Testing: {test['name']}")
        try:
            response = requests.post(f"{BASE_URL}/register", data=test['data'])
            if response.status_code == 400:
                print(f"    ✅ Correctly rejected: {response.json().get('detail', 'Validation error')}")
            else:
                print(f"    ❌ Should have been rejected but got: {response.status_code}")
        except Exception as e:
            print(f"    ❌ Error: {str(e)}")

def main():
    """Run all tests"""
    print("🚀 Starting Nigerian Road Risk Reporting App Tests")
    print("=" * 60)
    
    # Test 1: Check if server is running
    if not test_registration_form():
        print("\n❌ Server is not running. Please start the application first:")
        print("   python app.py")
        return
    
    # Test 2: Registration tests
    registration_results = test_user_registration()
    
    # Test 3: Identity verification (for first successful registration)
    successful_registrations = [r for r in registration_results if r['success']]
    if successful_registrations:
        first_user_id = successful_registrations[0]['user_id']
        test_identity_verification(first_user_id)
    
    # Test 4: List users
    test_list_users()
    
    # Test 5: Validation errors
    test_validation_errors()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    
    successful_tests = sum(1 for r in registration_results if r['success'])
    total_tests = len(registration_results)
    
    print(f"Registration Tests: {successful_tests}/{total_tests} successful")
    
    if successful_tests == total_tests:
        print("🎉 All tests passed! The application is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the application configuration.")
    
    print("\n✅ Test completed!")

if __name__ == "__main__":
    main() 