# tests/integration/test_jwt.py
"""
Tests for JWT authentication utilities.

This module tests the JWT token creation, verification, and user authentication
functionality provided by app/auth/jwt.py.
"""

import pytest
from datetime import timedelta, timezone, datetime
from uuid import uuid4, UUID
from jose import jwt
from fastapi import HTTPException

from app.auth.jwt import (
    verify_password,
    get_password_hash,
    create_token,
    decode_token,
    get_current_user
)
from app.schemas.token import TokenType
from app.core.config import settings
from app.models.user import User


# ======================================================================================
# Password Hashing Tests
# ======================================================================================

def test_password_hashing():
    """Test password hashing and verification."""
    plain_password = "TestPassword123"
    hashed = get_password_hash(plain_password)
    
    # Verify hashed password is different from plain
    assert hashed != plain_password
    
    # Verify correct password
    assert verify_password(plain_password, hashed) is True
    
    # Verify wrong password
    assert verify_password("WrongPassword", hashed) is False


def test_password_hash_different_each_time():
    """Test that hashing the same password produces different hashes (due to salt)."""
    plain_password = "TestPassword123"
    hash1 = get_password_hash(plain_password)
    hash2 = get_password_hash(plain_password)
    
    # Hashes should be different due to random salt
    assert hash1 != hash2
    
    # But both should verify correctly
    assert verify_password(plain_password, hash1) is True
    assert verify_password(plain_password, hash2) is True


# ======================================================================================
# Token Creation Tests
# ======================================================================================

def test_create_token_with_custom_expires_delta():
    """
    Test create_token with custom expires_delta parameter.
    
    This tests the branch where expires_delta is provided, which sets
    expire = datetime.now(timezone.utc) + expires_delta
    """
    user_id = uuid4()
    custom_delta = timedelta(hours=2)
    
    # Create token with custom expiration
    token = create_token(
        user_id=user_id,
        token_type=TokenType.ACCESS,
        expires_delta=custom_delta
    )
    
    # Decode to verify expiration was set correctly
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.ACCESS.value
    
    # Verify expiration is roughly 2 hours from now
    exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    now = datetime.now(timezone.utc)
    time_diff = exp_time - now
    
    # Should be close to 2 hours (within 5 seconds tolerance)
    assert abs(time_diff.total_seconds() - 7200) < 5


def test_create_token_with_custom_expires_delta_refresh():
    """Test create_token with custom expires_delta for refresh token."""
    user_id = uuid4()
    custom_delta = timedelta(days=10)
    
    token = create_token(
        user_id=user_id,
        token_type=TokenType.REFRESH,
        expires_delta=custom_delta
    )
    
    payload = jwt.decode(
        token,
        settings.JWT_REFRESH_SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.REFRESH.value


# ======================================================================================
# Token Creation Tests
# ======================================================================================

def test_create_token_with_uuid_object():
    """
    Test create_token with UUID object
    
    This tests the branch where user_id is a UUID object and needs
    to be converted to string: user_id = str(user_id)
    """
    user_id = uuid4()  # UUID object, not string
    
    # Pass UUID object directly
    token = create_token(
        user_id=user_id,  # UUID object
        token_type=TokenType.ACCESS
    )
    
    # Decode and verify user_id was converted to string
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    # Should be stored as string in payload
    assert payload["sub"] == str(user_id)
    assert isinstance(payload["sub"], str)
    
    # Should be able to convert back to UUID
    assert UUID(payload["sub"]) == user_id


def test_create_token_with_string_user_id():
    """Test create_token with string user_id."""
    user_id = str(uuid4())  # Already a string
    
    token = create_token(
        user_id=user_id, 
        token_type=TokenType.ACCESS
    )
    
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    assert payload["sub"] == user_id


# ======================================================================================
# Token Creation - Default Expiration Tests
# ======================================================================================

def test_create_access_token_default_expiration():
    """Test access token creation with default expiration."""
    user_id = uuid4()
    
    token = create_token(
        user_id=user_id,
        token_type=TokenType.ACCESS
        # No expires_delta, uses default
    )
    
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.ACCESS.value
    assert "exp" in payload
    assert "iat" in payload
    assert "jti" in payload


def test_create_refresh_token_default_expiration():
    """Test refresh token creation with default expiration."""
    user_id = uuid4()
    
    token = create_token(
        user_id=user_id,
        token_type=TokenType.REFRESH
        # No expires_delta, uses default
    )
    
    payload = jwt.decode(
        token,
        settings.JWT_REFRESH_SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.REFRESH.value


# ======================================================================================
# Token Decoding Tests
# ======================================================================================

@pytest.mark.asyncio
async def test_decode_valid_access_token():
    """Test decoding a valid access token."""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    payload = await decode_token(token, TokenType.ACCESS)
    
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.ACCESS.value


@pytest.mark.asyncio
async def test_decode_valid_refresh_token():
    """Test decoding a valid refresh token."""
    user_id = uuid4()
    token = create_token(user_id, TokenType.REFRESH)
    
    payload = await decode_token(token, TokenType.REFRESH)
    
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.REFRESH.value


@pytest.mark.asyncio
async def test_decode_token_wrong_type():
    """Test decoding fails when token type doesn't match."""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    # Try to decode access token as refresh token
    with pytest.raises(HTTPException) as exc_info:
        await decode_token(token, TokenType.REFRESH)
    
    assert exc_info.value.status_code == 401
    assert "Invalid token type" in exc_info.value.detail


@pytest.mark.asyncio
async def test_decode_expired_token():
    """Test decoding an expired token."""
    user_id = uuid4()
    
    # Create token that expires immediately
    token = create_token(
        user_id,
        TokenType.ACCESS,
        expires_delta=timedelta(seconds=-1)  # Already expired
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await decode_token(token, TokenType.ACCESS)
    
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_decode_invalid_token():
    """Test decoding an invalid/malformed token."""
    with pytest.raises(HTTPException) as exc_info:
        await decode_token("invalid.token.here", TokenType.ACCESS)
    
    assert exc_info.value.status_code == 401


# ======================================================================================
# Token Payload Tests
# ======================================================================================

def test_token_contains_all_required_fields():
    """Test that created tokens contain all required fields."""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    
    # Verify all required fields exist
    assert "sub" in payload
    assert "type" in payload
    assert "exp" in payload
    assert "iat" in payload
    assert "jti" in payload
    
    # Verify jti is a valid hex string
    assert len(payload["jti"]) == 32  # 16 bytes = 32 hex characters


def test_token_jti_is_unique():
    """Test that each token gets a unique jti (JWT ID)."""
    user_id = uuid4()
    
    token1 = create_token(user_id, TokenType.ACCESS)
    token2 = create_token(user_id, TokenType.ACCESS)
    
    payload1 = jwt.decode(token1, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    payload2 = jwt.decode(token2, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    
    # JTIs should be different
    assert payload1["jti"] != payload2["jti"]


# ======================================================================================
# Token Creation Error Handling
# ======================================================================================

def test_create_token_encoding_error(monkeypatch):
    """
    Test create_token handles JWT encoding errors .
    
    This tests the exception handler when jwt.encode() raises an exception.
    """
    def mock_encode(*args, **kwargs):
        raise Exception("JWT encoding failed")
    
    # Mock jwt.encode to raise an exception
    monkeypatch.setattr(jwt, "encode", mock_encode)
    
    user_id = uuid4()
    
    with pytest.raises(HTTPException) as exc_info:
        create_token(user_id, TokenType.ACCESS)
    
    assert exc_info.value.status_code == 500
    assert "Could not create token" in exc_info.value.detail


# ======================================================================================
# Decode Token Tests
# ======================================================================================

@pytest.mark.asyncio
async def test_decode_token_with_blacklisted_token(monkeypatch):
    """
    Test decode_token with a blacklisted token.
    
    This tests the blacklist check that raises HTTPException when
    a token has been revoked.
    """
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    # Mock is_blacklisted to return True
    async def mock_is_blacklisted(jti):
        return True
    
    from app.auth import jwt as jwt_module
    monkeypatch.setattr(jwt_module, "is_blacklisted", mock_is_blacklisted)
    
    with pytest.raises(HTTPException) as exc_info:
        await decode_token(token, TokenType.ACCESS)
    
    assert exc_info.value.status_code == 401
    assert "revoked" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_decode_token_expired_signature():
    """
    Test decode_token with expired token.
    
    This tests the jwt.ExpiredSignatureError exception handler.
    """
    user_id = uuid4()
    
    # Create an already-expired token
    token = create_token(
        user_id,
        TokenType.ACCESS,
        expires_delta=timedelta(seconds=-10)
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await decode_token(token, TokenType.ACCESS)
    
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_decode_token_jwt_error():
    """
    Test decode_token with malformed token.
    
    This tests the general JWTError exception handler.
    """
    with pytest.raises(HTTPException) as exc_info:
        await decode_token("not.a.valid.jwt", TokenType.ACCESS)
    
    assert exc_info.value.status_code == 401
    assert "validate credentials" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_decode_token_verify_exp_false(monkeypatch):
    """
    Test decode_token with verify_exp=False.
    
    This tests the options parameter in jwt.decode.
    """
    user_id = uuid4()
    
    # Create an expired token
    token = create_token(
        user_id,
        TokenType.ACCESS,
        expires_delta=timedelta(seconds=-10)
    )
    
    # Mock is_blacklisted to return False
    async def mock_is_blacklisted(jti):
        return False
    
    from app.auth import jwt as jwt_module
    monkeypatch.setattr(jwt_module, "is_blacklisted", mock_is_blacklisted)
    
    # Should succeed with verify_exp=False
    payload = await decode_token(token, TokenType.ACCESS, verify_exp=False)
    
    assert payload["sub"] == str(user_id)


# ======================================================================================
# get_current_user Tests
# ======================================================================================

@pytest.mark.asyncio
async def test_get_current_user_success(db_session):
    """
    Test get_current_user with valid token and active user.
    """
    # Create a user
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "username": "testuser",
        "password": User.hash_password("TestPass123")
    }
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    
    # Create a token for this user
    token = create_token(user.id, TokenType.ACCESS)
    
    # Mock is_blacklisted to return False
    from unittest.mock import AsyncMock
    from app.auth import jwt as jwt_module
    jwt_module.is_blacklisted = AsyncMock(return_value=False)
    
    # Get current user
    current_user = await get_current_user(token=token, db=db_session)
    
    assert current_user.id == user.id
    assert current_user.email == user.email


@pytest.mark.asyncio
async def test_get_current_user_not_found(db_session):
    """
    Test get_current_user when user doesn't exist.
    
    This tests the HTTPException when user is None.
    """
    # Create token for non-existent user
    fake_user_id = uuid4()
    token = create_token(fake_user_id, TokenType.ACCESS)
    
    # Mock is_blacklisted to return False
    from unittest.mock import AsyncMock
    from app.auth import jwt as jwt_module
    jwt_module.is_blacklisted = AsyncMock(return_value=False)
    
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token=token, db=db_session)
    
    assert exc_info.value.status_code == 404
    assert "User not found" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_current_user_inactive(db_session):
    """
    Test get_current_user with inactive user.
    
    This tests the HTTPException when user.is_active is False.
    """
    # Create an inactive user
    user_data = {
        "first_name": "Inactive",
        "last_name": "User",
        "email": "inactive@example.com",
        "username": "inactiveuser",
        "password": User.hash_password("TestPass123"),
        "is_active": False  # Inactive user
    }
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    
    # Create a token for this user
    token = create_token(user.id, TokenType.ACCESS)
    
    # Mock is_blacklisted to return False
    from unittest.mock import AsyncMock
    from app.auth import jwt as jwt_module
    jwt_module.is_blacklisted = AsyncMock(return_value=False)
    
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token=token, db=db_session)
    
    assert exc_info.value.status_code == 400
    assert "Inactive user" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_current_user_exception_handling(db_session, monkeypatch):
    """
    Test get_current_user general exception handler.
    
    This tests the outer except block that catches any Exception.
    """
    # Create a token
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    # Mock decode_token to raise a generic exception
    async def mock_decode_token(*args, **kwargs):
        raise Exception("Something went wrong")
    
    from app.auth import jwt as jwt_module
    monkeypatch.setattr(jwt_module, "decode_token", mock_decode_token)
    
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token=token, db=db_session)
    
    assert exc_info.value.status_code == 401