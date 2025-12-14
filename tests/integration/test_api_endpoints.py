# tests/integration/test_api_endpoints.py
"""
API Endpoint Tests using FastAPI TestClient

These tests use TestClient which runs in-process and contributes to code coverage.
They complement the Playwright E2E tests by providing:
- Direct API testing without browser overhead
- Code coverage metrics for main.py
- Faster execution for CI/CD pipelines

Tests cover:
- BREAD operations (Browse, Read, Edit, Add, Delete)
- Positive scenarios (successful operations)
- Negative scenarios (unauthorized access, invalid inputs, error handling)
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from uuid import uuid4

@pytest.fixture
def client():
    """Provide a TestClient for in-process API testing"""
    return TestClient(app)

@pytest.fixture
def auth_headers(client, db_session):
    """
    Fixture that creates a user and returns authentication headers.
    This can be reused across multiple tests.
    """
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test_{unique_id}@example.com",
        "username": f"testuser_{unique_id}",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    
    # Register user
    reg_response = client.post("/auth/register", json=user_data)
    assert reg_response.status_code == 201
    
    # Login
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": user_data["password"]
    })
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# Health and Root Endpoints
# ==============================================================================

def test_api_health_endpoint(client):
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_api_root_endpoint(client):
    """Test the root endpoint returns HTML"""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


# ==============================================================================
# Authentication Endpoints
# ==============================================================================

def test_api_user_registration(client, db_session):
    """Test user registration via API"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "New",
        "last_name": "User",
        "email": f"newuser_{unique_id}@example.com",
        "username": f"newuser_{unique_id}",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 201
    
    data = response.json()
    assert data["username"] == user_data["username"]
    assert data["email"] == user_data["email"]
    assert data["first_name"] == user_data["first_name"]
    assert data["last_name"] == user_data["last_name"]
    assert data["is_active"] is True
    assert data["is_verified"] is False
    assert "id" in data


def test_api_user_login(client, db_session):
    """Test user login via API"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Login",
        "last_name": "Test",
        "email": f"login_{unique_id}@example.com",
        "username": f"loginuser_{unique_id}",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    
    # Register
    reg_response = client.post("/auth/register", json=user_data)
    assert reg_response.status_code == 201
    
    # Login
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": user_data["password"]
    })
    
    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["username"] == user_data["username"]
    assert data["email"] == user_data["email"]


def test_api_login_with_invalid_credentials(client, db_session):
    """Test login with invalid credentials returns 401"""
    response = client.post("/auth/login", json={
        "username": "nonexistent_user",
        "password": "WrongPassword123!"
    })
    
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_api_registration_duplicate_username(client, db_session):
    """Test registration with duplicate username fails"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Duplicate",
        "last_name": "User",
        "email": f"dup1_{unique_id}@example.com",
        "username": f"dupuser_{unique_id}",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    
    # First registration succeeds
    response1 = client.post("/auth/register", json=user_data)
    assert response1.status_code == 201
    
    # Second registration with same username fails
    user_data["email"] = f"dup2_{unique_id}@example.com"  # Different email
    response2 = client.post("/auth/register", json=user_data)
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"].lower()


def test_api_registration_password_mismatch(client, db_session):
    """Test registration with mismatched passwords fails"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Mismatch",
        "last_name": "User",
        "email": f"mismatch_{unique_id}@example.com",
        "username": f"mismatch_{unique_id}",
        "password": "SecurePass123!",
        "confirm_password": "DifferentPass123!"  # Doesn't match
    }
    
    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 422  # Validation error


# ==============================================================================
# BREAD Operations - Comprehensive Testing
# ==============================================================================

def test_api_complete_bread_workflow(client, auth_headers, db_session):
    """
    Test complete BREAD workflow in a single test:
    Browse (empty) → Add → Browse (with data) → Read → Edit → Browse (updated) → Delete → Browse (empty)
    """
    
    # BROWSE - Initially empty
    response = client.get("/calculations", headers=auth_headers)
    assert response.status_code == 200
    initial_calculations = response.json()
    initial_count = len(initial_calculations)
    
    # ADD - Create a calculation
    calc_data = {
        "type": "addition",
        "inputs": [10.5, 3, 2]
    }
    response = client.post("/calculations", json=calc_data, headers=auth_headers)
    assert response.status_code == 201
    created_calc = response.json()
    assert created_calc["type"] == "addition"
    assert created_calc["inputs"] == [10.5, 3, 2]
    assert created_calc["result"] == 15.5
    calc_id = created_calc["id"]
    
    # BROWSE - Now has one calculation
    response = client.get("/calculations", headers=auth_headers)
    assert response.status_code == 200
    calculations = response.json()
    assert len(calculations) == initial_count + 1
    assert any(c["id"] == calc_id for c in calculations)
    
    # READ - Get specific calculation
    response = client.get(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 200
    calc = response.json()
    assert calc["id"] == calc_id
    assert calc["type"] == "addition"
    assert calc["inputs"] == [10.5, 3, 2]
    assert calc["result"] == 15.5
    
    # EDIT - Update the calculation
    update_data = {"inputs": [20, 10, 5]}
    response = client.put(f"/calculations/{calc_id}", json=update_data, headers=auth_headers)
    assert response.status_code == 200
    updated_calc = response.json()
    assert updated_calc["inputs"] == [20, 10, 5]
    assert updated_calc["result"] == 35  # 20 + 10 + 5
    
    # BROWSE - Verify update is reflected
    response = client.get("/calculations", headers=auth_headers)
    assert response.status_code == 200
    calculations = response.json()
    calc_in_list = next(c for c in calculations if c["id"] == calc_id)
    assert calc_in_list["result"] == 35
    
    # DELETE - Remove the calculation
    response = client.delete(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 204
    
    # BROWSE - Back to initial count
    response = client.get("/calculations", headers=auth_headers)
    assert response.status_code == 200
    final_calculations = response.json()
    assert len(final_calculations) == initial_count
    assert not any(c["id"] == calc_id for c in final_calculations)
    
    # READ - Verify calculation is gone (404)
    response = client.get(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 404


# ==============================================================================
# ADD Operation Tests (POST /calculations)
# ==============================================================================

def test_api_create_calculation_addition(client, auth_headers, db_session):
    """Test creating an addition calculation"""
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [5, 10, 15]},
        headers=auth_headers
    )
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "addition"
    assert data["result"] == 30


def test_api_create_calculation_subtraction(client, auth_headers, db_session):
    """Test creating a subtraction calculation"""
    response = client.post(
        "/calculations",
        json={"type": "subtraction", "inputs": [100, 30, 20]},
        headers=auth_headers
    )
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "subtraction"
    assert data["result"] == 50  # 100 - 30 - 20


def test_api_create_calculation_multiplication(client, auth_headers, db_session):
    """Test creating a multiplication calculation"""
    response = client.post(
        "/calculations",
        json={"type": "multiplication", "inputs": [2, 3, 4]},
        headers=auth_headers
    )
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "multiplication"
    assert data["result"] == 24


def test_api_create_calculation_division(client, auth_headers, db_session):
    """Test creating a division calculation"""
    response = client.post(
        "/calculations",
        json={"type": "division", "inputs": [100, 2, 5]},
        headers=auth_headers
    )
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "division"
    assert data["result"] == 10


def test_api_create_calculation_with_floats(client, auth_headers, db_session):
    """Test creating calculations with float inputs"""
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1.5, 2.5, 3.5]},
        headers=auth_headers
    )
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 7.5


# ==============================================================================
# BROWSE Operation Tests (GET /calculations)
# ==============================================================================

def test_api_list_calculations_empty(client, auth_headers, db_session):
    """Test listing calculations when user has none"""
    response = client.get("/calculations", headers=auth_headers)
    assert response.status_code == 200
    # User might have calculations from other tests, so just check it's a list
    assert isinstance(response.json(), list)


def test_api_list_calculations_multiple(client, auth_headers, db_session):
    """Test listing multiple calculations"""
    # Create multiple calculations
    calc_types = [
        {"type": "addition", "inputs": [1, 2]},
        {"type": "subtraction", "inputs": [10, 5]},
        {"type": "multiplication", "inputs": [3, 4]}
    ]
    
    created_ids = []
    for calc_data in calc_types:
        response = client.post("/calculations", json=calc_data, headers=auth_headers)
        assert response.status_code == 201
        created_ids.append(response.json()["id"])
    
    # List all calculations
    response = client.get("/calculations", headers=auth_headers)
    assert response.status_code == 200
    calculations = response.json()
    
    # Verify all created calculations are in the list
    calc_ids_in_list = [c["id"] for c in calculations]
    for created_id in created_ids:
        assert created_id in calc_ids_in_list


def test_api_list_calculations_user_isolation(client, db_session):
    """Test that users only see their own calculations"""
    # Create two users
    user1_headers = create_user_and_login(client, "user1")
    user2_headers = create_user_and_login(client, "user2")
    
    # User 1 creates a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=user1_headers
    )
    assert response.status_code == 201
    user1_calc_id = response.json()["id"]
    
    # User 2 creates a calculation
    response = client.post(
        "/calculations",
        json={"type": "subtraction", "inputs": [10, 5]},
        headers=user2_headers
    )
    assert response.status_code == 201
    user2_calc_id = response.json()["id"]
    
    # User 1 should only see their calculation
    response = client.get("/calculations", headers=user1_headers)
    user1_calcs = response.json()
    user1_calc_ids = [c["id"] for c in user1_calcs]
    assert user1_calc_id in user1_calc_ids
    assert user2_calc_id not in user1_calc_ids
    
    # User 2 should only see their calculation
    response = client.get("/calculations", headers=user2_headers)
    user2_calcs = response.json()
    user2_calc_ids = [c["id"] for c in user2_calcs]
    assert user2_calc_id in user2_calc_ids
    assert user1_calc_id not in user2_calc_ids


# ==============================================================================
# READ Operation Tests (GET /calculations/{id})
# ==============================================================================

def test_api_get_calculation_by_id(client, auth_headers, db_session):
    """Test retrieving a specific calculation by ID"""
    # Create a calculation
    response = client.post(
        "/calculations",
        json={"type": "multiplication", "inputs": [7, 8]},
        headers=auth_headers
    )
    calc_id = response.json()["id"]
    
    # Get the calculation
    response = client.get(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == calc_id
    assert data["type"] == "multiplication"
    assert data["inputs"] == [7, 8]
    assert data["result"] == 56


def test_api_get_nonexistent_calculation(client, auth_headers, db_session):
    """Test getting a calculation that doesn't exist returns 404"""
    fake_id = str(uuid4())
    response = client.get(f"/calculations/{fake_id}", headers=auth_headers)
    assert response.status_code == 404


def test_api_get_calculation_invalid_uuid(client, auth_headers, db_session):
    """Test getting a calculation with invalid UUID format returns 400"""
    response = client.get("/calculations/not-a-valid-uuid", headers=auth_headers)
    assert response.status_code == 400
    assert "Invalid calculation id format" in response.json()["detail"]


def test_api_get_other_user_calculation(client, db_session):
    """Test that users cannot access other users' calculations"""
    # Create two users
    user1_headers = create_user_and_login(client, "user1")
    user2_headers = create_user_and_login(client, "user2")
    
    # User 1 creates a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [5, 5]},
        headers=user1_headers
    )
    user1_calc_id = response.json()["id"]
    
    # User 2 tries to access User 1's calculation
    response = client.get(f"/calculations/{user1_calc_id}", headers=user2_headers)
    assert response.status_code == 404  # Should not find it


# ==============================================================================
# EDIT Operation Tests (PUT /calculations/{id})
# ==============================================================================

def test_api_update_calculation(client, auth_headers, db_session):
    """Test updating a calculation's inputs"""
    # Create a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2, 3]},
        headers=auth_headers
    )
    calc_id = response.json()["id"]
    
    # Update it
    response = client.put(
        f"/calculations/{calc_id}",
        json={"inputs": [10, 20, 30]},
        headers=auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["inputs"] == [10, 20, 30]
    assert data["result"] == 60


def test_api_update_calculation_recalculates(client, auth_headers, db_session):
    """Test that updating inputs recalculates the result"""
    # Create multiplication: 2 * 3 = 6
    response = client.post(
        "/calculations",
        json={"type": "multiplication", "inputs": [2, 3]},
        headers=auth_headers
    )
    calc_id = response.json()["id"]
    
    # Update to 5 * 6 = 30
    response = client.put(
        f"/calculations/{calc_id}",
        json={"inputs": [5, 6]},
        headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["result"] == 30


def test_api_update_nonexistent_calculation(client, auth_headers, db_session):
    """Test updating a calculation that doesn't exist returns 404"""
    fake_id = str(uuid4())
    response = client.put(
        f"/calculations/{fake_id}",
        json={"inputs": [1, 2]},
        headers=auth_headers
    )
    assert response.status_code == 404


def test_api_update_calculation_invalid_uuid(client, auth_headers, db_session):
    """Test updating with invalid UUID format returns 400"""
    response = client.put(
        "/calculations/invalid-uuid",
        json={"inputs": [1, 2]},
        headers=auth_headers
    )
    assert response.status_code == 400


def test_api_update_other_user_calculation(client, db_session):
    """Test that users cannot update other users' calculations"""
    # Create two users
    user1_headers = create_user_and_login(client, "user1")
    user2_headers = create_user_and_login(client, "user2")
    
    # User 1 creates a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=user1_headers
    )
    user1_calc_id = response.json()["id"]
    
    # User 2 tries to update User 1's calculation
    response = client.put(
        f"/calculations/{user1_calc_id}",
        json={"inputs": [10, 20]},
        headers=user2_headers
    )
    assert response.status_code == 404


# ==============================================================================
# DELETE Operation Tests (DELETE /calculations/{id})
# ==============================================================================

def test_api_delete_calculation(client, auth_headers, db_session):
    """Test deleting a calculation"""
    # Create a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=auth_headers
    )
    calc_id = response.json()["id"]
    
    # Delete it
    response = client.delete(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 204
    
    # Verify it's gone
    response = client.get(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 404


def test_api_delete_nonexistent_calculation(client, auth_headers, db_session):
    """Test deleting a calculation that doesn't exist returns 404"""
    fake_id = str(uuid4())
    response = client.delete(f"/calculations/{fake_id}", headers=auth_headers)
    assert response.status_code == 404


def test_api_delete_calculation_invalid_uuid(client, auth_headers, db_session):
    """Test deleting with invalid UUID format returns 400"""
    response = client.delete("/calculations/invalid-uuid", headers=auth_headers)
    assert response.status_code == 400


def test_api_delete_other_user_calculation(client, db_session):
    """Test that users cannot delete other users' calculations"""
    # Create two users
    user1_headers = create_user_and_login(client, "user1")
    user2_headers = create_user_and_login(client, "user2")
    
    # User 1 creates a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=user1_headers
    )
    user1_calc_id = response.json()["id"]
    
    # User 2 tries to delete User 1's calculation
    response = client.delete(f"/calculations/{user1_calc_id}", headers=user2_headers)
    assert response.status_code == 404
    
    # Verify User 1's calculation still exists
    response = client.get(f"/calculations/{user1_calc_id}", headers=user1_headers)
    assert response.status_code == 200


# ==============================================================================
# Negative Test Cases - Invalid Inputs
# ==============================================================================

def test_api_create_calculation_invalid_type(client, auth_headers, db_session):
    """Test creating calculation with invalid type returns validation error"""
    response = client.post(
        "/calculations",
        json={"type": "invalid_operation", "inputs": [1, 2]},
        headers=auth_headers
    )
    assert response.status_code == 422  # Validation error


def test_api_create_calculation_single_input(client, auth_headers, db_session):
    """Test creating calculation with only one input fails"""
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [5]},
        headers=auth_headers
    )
    assert response.status_code == 422


def test_api_create_calculation_empty_inputs(client, auth_headers, db_session):
    """Test creating calculation with empty inputs fails"""
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": []},
        headers=auth_headers
    )
    assert response.status_code == 422


def test_api_create_calculation_non_numeric_inputs(client, auth_headers, db_session):
    """Test creating calculation with non-numeric inputs fails"""
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": ["a", "b"]},
        headers=auth_headers
    )
    assert response.status_code == 422


def test_api_create_calculation_division_by_zero(client, auth_headers, db_session):
    """Test creating division calculation with zero divisor fails"""
    response = client.post(
        "/calculations",
        json={"type": "division", "inputs": [10, 0]},
        headers=auth_headers
    )
    assert response.status_code == 422


def test_api_create_calculation_missing_type(client, auth_headers, db_session):
    """Test creating calculation without type field fails"""
    response = client.post(
        "/calculations",
        json={"inputs": [1, 2]},
        headers=auth_headers
    )
    assert response.status_code == 422


def test_api_create_calculation_missing_inputs(client, auth_headers, db_session):
    """Test creating calculation without inputs field fails"""
    response = client.post(
        "/calculations",
        json={"type": "addition"},
        headers=auth_headers
    )
    assert response.status_code == 422


def test_api_update_calculation_empty_inputs(client, auth_headers, db_session):
    """Test updating calculation with empty inputs fails"""
    # Create a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=auth_headers
    )
    calc_id = response.json()["id"]
    
    # Try to update with empty inputs
    response = client.put(
        f"/calculations/{calc_id}",
        json={"inputs": []},
        headers=auth_headers
    )
    assert response.status_code == 422


def test_api_update_calculation_single_input(client, auth_headers, db_session):
    """Test updating calculation with single input fails"""
    # Create a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=auth_headers
    )
    calc_id = response.json()["id"]
    
    # Try to update with single input
    response = client.put(
        f"/calculations/{calc_id}",
        json={"inputs": [5]},
        headers=auth_headers
    )
    assert response.status_code == 422


# ==============================================================================
# Negative Test Cases - Unauthorized Access
# ==============================================================================

def test_api_list_calculations_without_auth(client):
    """Test listing calculations without authentication returns 401"""
    response = client.get("/calculations")
    assert response.status_code == 401


def test_api_get_calculation_without_auth(client):
    """Test getting a calculation without authentication returns 401"""
    fake_id = str(uuid4())
    response = client.get(f"/calculations/{fake_id}")
    assert response.status_code == 401


def test_api_create_calculation_without_auth(client):
    """Test creating a calculation without authentication returns 401"""
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]}
    )
    assert response.status_code == 401


def test_api_update_calculation_without_auth(client):
    """Test updating a calculation without authentication returns 401"""
    fake_id = str(uuid4())
    response = client.put(
        f"/calculations/{fake_id}",
        json={"inputs": [1, 2]}
    )
    assert response.status_code == 401


def test_api_delete_calculation_without_auth(client):
    """Test deleting a calculation without authentication returns 401"""
    fake_id = str(uuid4())
    response = client.delete(f"/calculations/{fake_id}")
    assert response.status_code == 401


def test_api_access_with_invalid_token(client, db_session):
    """Test accessing endpoints with invalid token returns 401"""
    headers = {"Authorization": "Bearer invalid.token.here"}
    
    response = client.get("/calculations", headers=headers)
    assert response.status_code == 401


# ==============================================================================
# Helper Functions
# ==============================================================================

def create_user_and_login(client, username_prefix: str) -> dict:
    """
    Helper function to create a user and return authentication headers.
    
    Args:
        client: TestClient instance
        username_prefix: Prefix for username to ensure uniqueness
        
    Returns:
        Dictionary with Authorization header
    """
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": username_prefix.title(),
        "last_name": "Test",
        "email": f"{username_prefix}_{unique_id}@example.com",
        "username": f"{username_prefix}_{unique_id}",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    
    # Register
    reg_response = client.post("/auth/register", json=user_data)
    assert reg_response.status_code == 201
    
    # Login
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": user_data["password"]
    })
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}