import pytest
from src.auth import (
    create_access_token,
    verify_access_token,
    hash_password,
    verify_password,
)

def test_password_hashing():
    password = "password123"
    hashed_password = hash_password(password)

    # Ensure password is hashed
    assert password != hashed_password
    assert verify_password("password123", hashed_password) is True
    assert verify_password("password1234", hashed_password) is False
