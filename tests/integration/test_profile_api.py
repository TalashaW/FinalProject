# tests/integration/test_profile_api.py
"""
Integration Tests for Profile API Endpoints

Tests cover:
- GET /api/profile - Retrieve user profile
- PUT /api/profile - Update user profile
- POST /api/profile/change-password - Change password

These tests use TestClient for in-process testing with code coverage.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from uuid import uuid4
from app.models.user import User

@pytest.fixture
def client():
    """Provide a TestClient for in-process API testing"""
    return TestClient(app)


@pytest.fixture
def test_user_with_token(client, db_session):
    """
    Create a test user and return both user data and auth token.
    """
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Profile",
        "last_name": "Test",
        "email": f"profile_{unique_id}@example.com",
        "username": f"profiletest_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register user
    reg_response = client.post("/auth/register", json=user_data)
    assert reg_response.status_code == 201
    
    # Login to get token
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": user_data["password"]
    })
    assert login_response.status_code == 200
    token_data = login_response.json()
    
    return {
        "user_data": user_data,
        "token": token_data["access_token"],
        "user_id": token_data["user_id"],
        "headers": {"Authorization": f"Bearer {token_data['access_token']}"}
    }


# ==============================================================================
# GET /api/profile Tests
# ==============================================================================

def test_get_profile_success(client, test_user_with_token):
    """Test successfully retrieving user profile"""
    response = client.get("/api/profile", headers=test_user_with_token["headers"])
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify all profile fields are present
    assert data["username"] == test_user_with_token["user_data"]["username"]
    assert data["email"] == test_user_with_token["user_data"]["email"]
    assert data["first_name"] == test_user_with_token["user_data"]["first_name"]
    assert data["last_name"] == test_user_with_token["user_data"]["last_name"]
    assert data["is_active"] is True
    assert "id" in data
    assert "created_at" in data
    assert "updated_at" in data


def test_get_profile_without_auth(client):
    """Test getting profile without authentication returns 401"""
    response = client.get("/api/profile")
    assert response.status_code == 401


def test_get_profile_invalid_token(client):
    """Test getting profile with invalid token returns 401"""
    headers = {"Authorization": "Bearer invalid.token.here"}
    response = client.get("/api/profile", headers=headers)
    assert response.status_code == 401


# ==============================================================================
# PUT /api/profile Tests
# ==============================================================================

def test_update_profile_all_fields(client, test_user_with_token):
    """Test updating all profile fields successfully"""
    unique_id = str(uuid4())[:8]
    update_data = {
        "username": f"updated_{unique_id}",
        "email": f"updated_{unique_id}@example.com",
        "first_name": "Updated",
        "last_name": "User"
    }
    
    response = client.put(
        "/api/profile",
        json=update_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["username"] == update_data["username"]
    assert data["email"] == update_data["email"]
    assert data["first_name"] == update_data["first_name"]
    assert data["last_name"] == update_data["last_name"]


def test_update_profile_partial(client, test_user_with_token):
    """Test updating only some profile fields"""
    update_data = {
        "first_name": "PartialUpdate"
    }
    
    response = client.put(
        "/api/profile",
        json=update_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Updated field
    assert data["first_name"] == "PartialUpdate"
    
    # Unchanged fields should remain the same
    assert data["username"] == test_user_with_token["user_data"]["username"]
    assert data["email"] == test_user_with_token["user_data"]["email"]


def test_update_profile_duplicate_username(client, test_user_with_token, db_session):
    """Test updating username to one that already exists returns 409"""
    # Create another user
    unique_id = str(uuid4())[:8]
    other_user_data = {
        "first_name": "Other",
        "last_name": "User",
        "email": f"other_{unique_id}@example.com",
        "username": f"otheruser_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    client.post("/auth/register", json=other_user_data)
    
    # Try to update first user's username to the second user's username
    update_data = {
        "username": other_user_data["username"]
    }
    
    response = client.put(
        "/api/profile",
        json=update_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 409
    assert "Username already taken" in response.json()["detail"]


def test_update_profile_duplicate_email(client, test_user_with_token, db_session):
    """Test updating email to one that already exists returns 409"""
    # Create another user
    unique_id = str(uuid4())[:8]
    other_user_data = {
        "first_name": "Other",
        "last_name": "User",
        "email": f"other_{unique_id}@example.com",
        "username": f"otheruser_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    client.post("/auth/register", json=other_user_data)
    
    # Try to update first user's email to the second user's email
    update_data = {
        "email": other_user_data["email"]
    }
    
    response = client.put(
        "/api/profile",
        json=update_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 409
    assert "Email already in use" in response.json()["detail"]


def test_update_profile_without_auth(client):
    """Test updating profile without authentication returns 401"""
    update_data = {"first_name": "Unauthorized"}
    response = client.put("/api/profile", json=update_data)
    assert response.status_code == 401


def test_update_profile_invalid_email(client, test_user_with_token):
    """Test updating with invalid email format returns validation error"""
    update_data = {"email": "invalid-email"}
    
    response = client.put(
        "/api/profile",
        json=update_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 422  # Validation error


# ==============================================================================
# POST /api/profile/change-password Tests
# ==============================================================================

def test_change_password_success(client, test_user_with_token):
    """Test successfully changing password"""
    password_data = {
        "current_password": "TestPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    
    response = client.post(
        "/api/profile/change-password",
        json=password_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "Password changed successfully" in data["message"]
    
    # Verify can login with new password
    login_response = client.post("/auth/login", json={
        "username": test_user_with_token["user_data"]["username"],
        "password": "NewPass456!"
    })
    assert login_response.status_code == 200


def test_change_password_wrong_current(client, test_user_with_token):
    """Test changing password with incorrect current password returns 401"""
    password_data = {
        "current_password": "WrongPassword123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    
    response = client.post(
        "/api/profile/change-password",
        json=password_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 401
    assert "Current password is incorrect" in response.json()["detail"]


def test_change_password_mismatch(client, test_user_with_token):
    """Test changing password when new passwords don't match returns 400"""
    password_data = {
        "current_password": "TestPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "DifferentPass789!"
    }
    
    response = client.post(
        "/api/profile/change-password",
        json=password_data,
        headers=test_user_with_token["headers"]
    )
    
    # This validation happens at Pydantic schema level
    assert response.status_code == 422


def test_change_password_same_as_current(client, test_user_with_token):
    """Test changing password to same as current returns 400"""
    password_data = {
        "current_password": "TestPass123!",
        "new_password": "TestPass123!",
        "confirm_new_password": "TestPass123!"
    }
    
    response = client.post(
        "/api/profile/change-password",
        json=password_data,
        headers=test_user_with_token["headers"]
    )
    
    assert response.status_code == 400
    assert "must be different from current password" in response.json()["detail"]


def test_change_password_without_auth(client):
    """Test changing password without authentication returns 401"""
    password_data = {
        "current_password": "TestPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    
    response = client.post("/api/profile/change-password", json=password_data)
    assert response.status_code == 401


def test_change_password_weak_password(client, test_user_with_token):
    """Test changing to a weak password returns validation error"""
    password_data = {
        "current_password": "TestPass123!",
        "new_password": "weak",  # Too short, missing requirements
        "confirm_new_password": "weak"
    }
    
    response = client.post(
        "/api/profile/change-password",
        json=password_data,
        headers=test_user_with_token["headers"]
    )
    
    # Pydantic validation error
    assert response.status_code == 422


# ==============================================================================
# Edge Cases and Error Handling
# ==============================================================================

def test_update_profile_empty_fields(client, test_user_with_token):
    """Test updating with empty strings is rejected"""
    update_data = {
        "first_name": "",
        "last_name": ""
    }
    
    response = client.put(
        "/api/profile",
        json=update_data,
        headers=test_user_with_token["headers"]
    )
    
    # Should fail validation (min_length=1)
    assert response.status_code == 422


def test_profile_updates_timestamp(client, test_user_with_token):
    """Test that updating profile updates the updated_at timestamp"""
    # Get initial profile
    initial_response = client.get("/api/profile", headers=test_user_with_token["headers"])
    initial_data = initial_response.json()
    initial_updated_at = initial_data["updated_at"]
    
    # Wait a moment
    import time
    time.sleep(0.1)
    
    # Update profile
    update_data = {"first_name": "Updated"}
    client.put("/api/profile", json=update_data, headers=test_user_with_token["headers"])
    
    # Get updated profile
    updated_response = client.get("/api/profile", headers=test_user_with_token["headers"])
    updated_data = updated_response.json()
    updated_updated_at = updated_data["updated_at"]
    
    # Timestamp should have changed
    assert updated_updated_at != initial_updated_at


def test_change_password_updates_timestamp(client, test_user_with_token, db_session):
    """Test that changing password updates the updated_at timestamp"""
    # Get initial profile
    initial_response = client.get("/api/profile", headers=test_user_with_token["headers"])
    initial_data = initial_response.json()
    initial_updated_at = initial_data["updated_at"]
    
    # Wait a moment
    import time
    time.sleep(0.1)
    
    # Change password
    password_data = {
        "current_password": "TestPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    client.post("/api/profile/change-password", json=password_data, headers=test_user_with_token["headers"])
    
    # Get updated profile
    updated_response = client.get("/api/profile", headers=test_user_with_token["headers"])
    updated_data = updated_response.json()
    updated_updated_at = updated_data["updated_at"]
    
    # Timestamp should have changed
    assert updated_updated_at != initial_updated_at