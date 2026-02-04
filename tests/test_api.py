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


def test_login_flow(client):
    test_user = {
        "username": "testuser123",
        "password": "password123",
        "confirm_password": "password123",
    }

    client.post("/register", json=test_user)

    test_user_login = {"username": "testuser123", "password": "password123"}

    # Uses data= instead of json= because of OAuth2
    response = client.post("/login", data=test_user_login)

    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_password_mismatch(client):
    test_user = {
        "username": "testuser123",
        "password": "password123",
        "confirm_password": "password123",
    }

    client.post("/register", json=test_user)

    test_user_login = {"username": "testuser123", "password": "password1234"}

    response = client.post("/login", data=test_user_login)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"

    data = response.json()
    assert data["detail"] == "Invalid username or password"


def test_login_nonexistent_user(client):
    test_user_login = {"username": "testuser123", "password": "password123"}

    response = client.post("/login", data=test_user_login)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"

    data = response.json()
    assert data["detail"] == "Invalid username or password"


def test_get_user_page_success(client):
    test_user = {
        "username": "testuser123",
        "password": "password123",
        "confirm_password": "password123",
    }

    client.post("/register", json=test_user)

    test_user_login = {"username": "testuser123", "password": "password123"}

    login_response = client.post("/login", data=test_user_login)
    data = login_response.json()
    token = data["access_token"]

    # Authorization: Bearer <token> is part of the RFC 6750 standard
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/me", headers=headers)

    assert response.status_code == 200
    assert response.json()["message"] == "Hello testuser123, welcome to your page!"


def test_get_user_page_unauthorised(client):
    response = client.get("/me")
    assert response.status_code == 401
