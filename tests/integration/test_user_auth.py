# tests/integration/test_user_auth.py

import pytest
from uuid import UUID
from jose import jwt
import pydantic_core
from sqlalchemy.exc import IntegrityError
from app.core.config import settings
from app.models.user import User

def test_password_hashing(db_session, fake_user_data):
    """Test password hashing and verification functionality"""
    original_password = "TestPass123"  # Use known password for test
    hashed = User.hash_password(original_password)
    
    user = User(
        first_name=fake_user_data['first_name'],
        last_name=fake_user_data['last_name'],
        email=fake_user_data['email'],
        username=fake_user_data['username'],
        password=hashed
    )
    
    assert user.verify_password(original_password) is True
    assert user.verify_password("WrongPass123") is False
    assert hashed != original_password

def test_user_registration(db_session, fake_user_data):
    """Test user registration process"""
    fake_user_data['password'] = "TestPass123"
    
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.first_name == fake_user_data['first_name']
    assert user.last_name == fake_user_data['last_name']
    assert user.email == fake_user_data['email']
    assert user.username == fake_user_data['username']
    assert user.is_active is True
    assert user.is_verified is False
    assert user.verify_password("TestPass123") is True

def test_duplicate_user_registration(db_session):
    """Test registration with duplicate email/username"""
    # First user data
    user1_data = {
        "first_name": "Test",
        "last_name": "User1",
        "email": "unique.test@example.com",
        "username": "uniqueuser1",
        "password": "TestPass123"
    }
    
    # Second user data with same email
    user2_data = {
        "first_name": "Test",
        "last_name": "User2",
        "email": "unique.test@example.com",  # Same email
        "username": "uniqueuser2",
        "password": "TestPass123"
    }
    
    # Register first user
    first_user = User.register(db_session, user1_data)
    db_session.commit()
    db_session.refresh(first_user)
    
    # Try to register second user with same email
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user2_data)

def test_user_authentication(db_session, fake_user_data):
    """Test user authentication and token generation"""
    # Use fake_user_data from fixture
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Test successful authentication
    auth_result = User.authenticate(
        db_session,
        fake_user_data['username'],
        "TestPass123"
    )
    
    assert auth_result is not None
    assert "access_token" in auth_result
    assert "token_type" in auth_result
    assert auth_result["token_type"] == "bearer"
    assert "user" in auth_result

def test_user_last_login_update(db_session, fake_user_data):
    """Test that last_login is updated on authentication"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Authenticate and check last_login
    assert user.last_login is None
    auth_result = User.authenticate(db_session, fake_user_data['username'], "TestPass123")
    db_session.refresh(user)
    assert user.last_login is not None

def test_unique_email_username(db_session):
    """Test uniqueness constraints for email and username"""
    # Create first user with specific test data
    user1_data = {
        "first_name": "Test",
        "last_name": "User1",
        "email": "unique_test@example.com",
        "username": "uniqueuser",
        "password": "TestPass123"
    }
    
    # Register and commit first user
    User.register(db_session, user1_data)
    db_session.commit()
    
    # Try to create user with same email
    user2_data = {
        "first_name": "Test",
        "last_name": "User2",
        "email": "unique_test@example.com",  # Same email
        "username": "differentuser",
        "password": "TestPass123"
    }
    
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user2_data)

def test_short_password_registration(db_session):
    """Test that registration fails with a short password"""
    # Prepare test data with a 5-character password
    test_data = {
        "first_name": "Password",
        "last_name": "Test",
        "email": "short.pass@example.com",
        "username": "shortpass",
        "password": "Shor1"  # 5 characters, should fail
    }
    
    # Attempt registration with short password
    with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
        User.register(db_session, test_data)

def test_invalid_token():
    """Test that invalid tokens are rejected"""
    invalid_token = "invalid.token.string"
    result = User.verify_token(invalid_token)
    assert result is None

def test_token_creation_and_verification(db_session, fake_user_data):
    """Test token creation and verification"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Create token
    token = User.create_access_token({"sub": str(user.id)})
    
    # Verify token
    decoded_user_id = User.verify_token(token)
    assert decoded_user_id == user.id

def test_authenticate_with_email(db_session, fake_user_data):
    """Test authentication using email instead of username"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Test authentication with email
    auth_result = User.authenticate(
        db_session,
        fake_user_data['email'],  # Using email instead of username
        "TestPass123"
    )
    
    assert auth_result is not None
    assert "access_token" in auth_result

def test_user_model_representation(test_user):
    """Test the string representation of User model"""
    expected = f"<User(name={test_user.first_name} {test_user.last_name}, email={test_user.email})>"
    assert str(test_user) == expected

def test_missing_password_registration(db_session):
    """Test that registration fails when no password is provided."""
    test_data = {
        "first_name": "NoPassword",
        "last_name": "Test",
        "email": "no.password@example.com",
        "username": "nopassworduser",
        # Password is missing
    }
    
    # Adjust the expected error message
    with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
        User.register(db_session, test_data)

def test_user_init_with_hashed_password(db_session):
    """
    Test User.__init__ with hashed_password kwarg (line 109).
    
    This tests the special handling in __init__ where 'hashed_password' 
    is renamed to 'password' internally.
    """
    # Create a hashed password
    plain_password = "TestPassword123"
    hashed = User.hash_password(plain_password)
    
    # Use hashed_password kwarg instead of password
    user = User(
        first_name="Init",
        last_name="Test",
        email="init.test@example.com",
        username="inittest",
        hashed_password=hashed  # This triggers line 109
    )
    
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    
    # Verify the password was set correctly
    assert user.password == hashed
    assert user.verify_password(plain_password) is True
    assert "hashed_password" not in user.__dict__  # Should not exist as attribute


def test_verify_token_missing_sub_claim():
    """
    Test User.verify_token with a token missing 'sub' claim (line 221).
    
    This tests the case where a valid JWT token is provided but it 
    doesn't contain the 'sub' (subject) claim.
    """
    # Create a JWT token without a 'sub' claim
    payload = {
        "some_other_claim": "value",
        "iat": 1234567890
        # Note: No "sub" field
    }
    
    token = jwt.encode(
        payload, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    # Verify token should return None because there's no 'sub' claim
    result = User.verify_token(token)
    assert result is None  # This tests line 221


def test_verify_token_sub_none():
    """
    Test User.verify_token when 'sub' claim exists but is None.
    
    This is another edge case for line 221 where sub explicitly equals None.
    """
    # Create a token with sub = None
    payload = {
        "sub": None  # Explicitly None
    }
    
    token = jwt.encode(
        payload, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    result = User.verify_token(token)
    assert result is None  # This also tests line 221

def test_verify_token_invalid_uuid_format():
    """
    Test User.verify_token with a 'sub' that cannot be converted to UUID (line 221).
    
    This tests the case where 'sub' exists but is not a valid UUID string,
    causing uuid.UUID() to raise ValueError, which triggers line 221.
    """
    # Create a token with an invalid UUID string in 'sub'
    payload = {
        "sub": "not-a-valid-uuid-string"  # This will fail UUID conversion
    }
    
    token = jwt.encode(
        payload, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    # This should trigger the ValueError in uuid.UUID() conversion
    # and return None at line 221
    result = User.verify_token(token)
    assert result is None


def test_verify_token_numeric_sub():
    """
    Test User.verify_token with a numeric 'sub' (line 221).
    
    This tests another case where 'sub' exists but is the wrong type
    (integer instead of string), causing TypeError in uuid.UUID().
    """
    # Create a token with a number as 'sub'
    payload = {
        "sub": 12345  # Integer instead of UUID string
    }
    
    token = jwt.encode(
        payload, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    # This should trigger TypeError in uuid.UUID() conversion
    # and return None at line 221
    result = User.verify_token(token)
    assert result is None

# Add these tests to test_user_auth.py

def test_authenticate_nonexistent_user(db_session):
    """
    Test authentication with a username that doesn't exist (line 221).
    
    This triggers the 'if not user' part of the condition on line 221,
    where no user is found in the database.
    """
    # Try to authenticate with a username that doesn't exist
    result = User.authenticate(
        db_session,
        "nonexistent_username",
        "SomePassword123"
    )
    
    # Should return None because user doesn't exist
    assert result is None


def test_authenticate_wrong_password(db_session, fake_user_data):
    """
    Test authentication with wrong password (line 221).
    
    This triggers the 'not user.verify_password(password)' part of line 221,
    where the user exists but the password is incorrect.
    """
    # Register a user with a known password
    fake_user_data['password'] = "CorrectPassword123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Try to authenticate with wrong password
    result = User.authenticate(
        db_session,
        fake_user_data['username'],
        "WrongPassword456"  # Wrong password
    )
    
    # Should return None because password is wrong
    assert result is None


def test_authenticate_nonexistent_email(db_session):
    """
    Test authentication with an email that doesn't exist (line 221).
    
    This covers authentication via email (not username) when user doesn't exist.
    """
    # Try to authenticate with an email that doesn't exist
    result = User.authenticate(
        db_session,
        "nonexistent@example.com",  # Using email format
        "SomePassword123"
    )
    
    # Should return None because user doesn't exist
    assert result is None  