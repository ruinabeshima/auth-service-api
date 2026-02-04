import pytest


def test_register_flow(client):
    test_user = {
        "username": "testuser123",
        "password": "password123",
        "confirm_password": "password123",
    }
    response = client.post("/register", json=test_user)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "testuser123"
    assert data["message"] == "Register successful"


def test_register_duplicate_username(client):
    test_user = {
        "username": "testuser123",
        "password": "password123",
        "confirm_password": "password123",
    }
    client.post("/register", json=test_user)
    response = client.post("/register", json=test_user)
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Username already exists"


def test_register_passwords_mismatch(client):
    test_user = {
        "username": "testuser123",
        "password": "password123",
        "confirm_password": "wrong_password123",
    }
    response = client.post("/register", json=test_user)
    assert response.status_code == 422
    data = response.json()
    assert data["detail"][0]["msg"] == "Value error, Passwords do not match"
