import pytest
import jwt
import os
from fastapi import HTTPException
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from src.auth import (
    create_access_token,
    verify_access_token,
    hash_password,
    verify_password,
    create_reset_token,
    verify_reset_token,
    create_refresh_token,
    get_refresh_token_expiry,
)
from src.schemas import TokenData

load_dotenv()

# Environment variables
secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")
algorithm = os.getenv("ALGORITHM", "HS256")


# Testing if password is hashed correctly
def test_password_hashing_logic():
    password = "password123"
    hashed_password = hash_password(password)

    assert password != hashed_password
    assert verify_password("password123", hashed_password) is True
    assert verify_password("password1234", hashed_password) is False


# Testing if access token is created and verified correctly
def test_access_token_logic():
    data = TokenData(username="user1")
    token = create_access_token(data)

    decoded = verify_access_token(token)
    assert decoded["sub"] == "user1"
    assert "exp" in decoded


# Testing verification of an invalid token
def test_verify_access_token_invalid():
    with pytest.raises(HTTPException) as exc:
        verify_access_token("invalid-token-value")

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"


# Testing verification of an expired token
def test_verify_access_token_expired():
    data = TokenData(username="user1")
    payload = {
        "sub": data.username,
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        "iat": datetime.now(timezone.utc) - timedelta(minutes=5),
    }

    encoded_jwt = jwt.encode(payload, secret_key, algorithm=algorithm)

    with pytest.raises(HTTPException) as exc:
        verify_access_token(encoded_jwt)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Token has expired"


# Testing if reset token is created and verified properly
def test_reset_token_logic():
    data = "user1@email.com"
    token = create_reset_token(data)

    decoded = verify_reset_token(token)
    assert decoded["sub"] == "user1@email.com"
    assert decoded["type"] == "password-reset"
    assert "exp" in decoded


# Testing if refresh token is created properly
def test_create_refresh_token():
    refresh_token = create_refresh_token()

    assert isinstance(refresh_token, str)
    assert len(refresh_token) > 30

    another_token = create_refresh_token()
    assert refresh_token != another_token


# Testing if refresh token expiry date works 
def test_get_refresh_token_expiry(): 
    expiry = get_refresh_token_expiry() 
    now = datetime.now(timezone.utc)

    # Expiry time should be in the future 
    assert expiry > now 

    # Should be approximately 7 days from now (within 1 minute tolerance)
    expected = now + timedelta(days=7)
    time_difference = abs((expiry - expected).total_seconds())
    assert time_difference < 60


