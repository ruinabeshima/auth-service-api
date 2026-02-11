import pytest


class TestRegister:
    def test_register_flow(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "password123",
        }

        response = client.post("/register", json=test_user)

        assert response.status_code == 201

        data = response.json()
        assert data["username"] == "testuser123"
        assert data["message"] == "Register successful"

    def test_register_duplicate_username(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "password123",
        }

        new_test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser1@email.com",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        response = client.post("/register", json=new_test_user)

        assert response.status_code == 400
        data = response.json()
        assert data["detail"] == "Username already exists"

    def test_register_duplicate_email(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "password123",
        }

        new_test_user = {
            "username": "testuser1234",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        response = client.post("/register", json=new_test_user)

        assert response.status_code == 400
        data = response.json()
        assert data["detail"] == "Email already exists"

    def test_register_passwords_mismatch(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "wrong_password123",
        }
        response = client.post("/register", json=test_user)

        assert response.status_code == 422

        data = response.json()
        assert data["detail"][0]["msg"] == "Value error, Passwords do not match"


class TestLogin:
    def test_login_flow_username(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        test_user_login = {"username": "testuser123", "password": "password123"}

        # Uses data= instead of json= because of OAuth2
        response = client.post("/login", data=test_user_login)

        assert response.status_code == 200

        data = response.json()
        assert "refresh_token" in data
        assert isinstance(data["refresh_token"], str)
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        assert data["token_type"] == "bearer"

    def test_login_flow_email(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        test_user_login = {"username": "testuser@email.com", "password": "password123"}

        # Uses data= instead of json= because of OAuth2
        response = client.post("/login", data=test_user_login)

        assert response.status_code == 200

        data = response.json()
        assert "refresh_token" in data
        assert isinstance(data["refresh_token"], str)
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        assert data["token_type"] == "bearer"

    def test_login_password_mismatch(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser123@email.com",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        test_user_login = {"username": "testuser123", "password": "password1234"}

        response = client.post("/login", data=test_user_login)

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

        data = response.json()
        assert data["detail"] == "Invalid credentials"

    def test_login_nonexistent_user(self, client):
        test_user_login = {"username": "testuser123", "password": "password123"}

        response = client.post("/login", data=test_user_login)

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

        data = response.json()
        assert data["detail"] == "Invalid credentials"


class TestUserPage:
    def test_get_user_page_success(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser123@email.com",
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
        assert "username" in response.json() 
        assert "email" in response.json() 
        assert "role" in response.json() 
        assert response.json()["role"] == "user"

    def test_get_user_page_unauthorised(self, client):
        response = client.get("/me")
        assert response.status_code == 401


class TestForgotPassword:
    def test_forgot_reset_password_flow(self, client):
        test_user = {
            "username": "testuser123",
            "email": "user1@email.com",
            "password": "password123",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        forgot_password_data = {"email": "user1@email.com"}
        response = client.post("/forgot-password", json=forgot_password_data)

        assert response.status_code == 200

        data = response.json()
        assert data["message"] == "If the account exists, a reset link has been sent"
        assert "reset_token" in data

        reset_data = {
            "token": data["reset_token"],
            "new_password": "new_password",
            "confirm_password": "new_password",
        }
        reset_response = client.post("/reset-password", json=reset_data)

        assert reset_response.status_code == 200
        data = reset_response.json()
        assert data["message"] == "Password reset successful"

    def test_forgot_password_nonexistent_user(self, client):
        test_user = {
            "username": "testuser123",
            "email": "user1@email.com",
            "password": "password123",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        forgot_password_data = {"email": "user2@email.com"}
        response = client.post("/forgot-password", json=forgot_password_data)

        assert response.status_code == 200

        data = response.json()
        assert data["message"] == "If the account exists, a reset link has been sent"
        assert "reset_token" not in data


class TestRefreshToken:
    def test_refresh_token_flow(self, client):
        test_user = {
            "username": "testuser123",
            "password": "password123",
            "email": "testuser@email.com",
            "confirm_password": "password123",
        }

        client.post("/register", json=test_user)

        test_user_login = {"username": "testuser123", "password": "password123"}

        login_response = client.post("/login", data=test_user_login)

        refresh_token = login_response.json()["refresh_token"]

        refresh_response = client.post(
            "/refresh", json={"refresh_token": refresh_token}
        )
        refresh_data = refresh_response.json()

        # Refresh token should be different
        assert refresh_data["refresh_token"] != refresh_token

        # Previous token should not work
        old_token_response = client.post(
            "/refresh", json={"refresh_token": refresh_token}
        )
        assert old_token_response.status_code == 401