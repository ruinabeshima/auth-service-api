import pytest
from src.auth import (
    create_access_token,
    verify_access_token,
    hash_password,
    verify_password,
)
from src.schemas import TokenData


def test_password_hashing_logic():
    password = "password123"
    hashed_password = hash_password(password)

    # Ensure password is hashed
    assert password != hashed_password
    assert verify_password("password123", hashed_password) is True
    assert verify_password("password1234", hashed_password) is False


def test_access_token_logic():
    data = TokenData(username="user1")
    token = create_access_token(data)

    decoded = verify_access_token(token)
    assert decoded["sub"] == "user1"
    assert "exp" in decoded
