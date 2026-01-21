from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import bcrypt

# TEMPORARY: User dictionary
users = {}


# User models
class RegisterUser(BaseModel):
    username: str
    password: str
    confirm_password: str


class LoginUser(BaseModel):
    username: str
    password: str


# Helper function for hashing password
def hash_password(password: str):
    # Convert plain text password to bytes
    password_bytes = password.encode("utf-8")
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password using the salt
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    # Convert resulting bytes back to a string for easy storage
    return hashed_password.decode("utf-8")


# Helper function to verify password
def verify_password(plain_password: str, hashed_password: str):
    plain_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


app = FastAPI()


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: RegisterUser):

    # Raise exception - input passwords do not match
    if user.password != user.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match"
        )

    # Hash password
    hashed_password = hash_password(user.password)

    # TEMPORARY: Add user to dictionary
    users[user.username] = hashed_password

    # Return response object with no passwords for security
    return {
        "username": user.username,
        "message": "Register successful",
    }


@app.post("/login")
def login_user(user: LoginUser):

    # TEMPORARY: Get user from dictionary
    hashed_password = users.get(user.username)

    # Raise exception - password does not match / user account doesn't exist
    if not hashed_password or not verify_password(user.password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            # WWW-Authenticate: Signals to the browser that user can be authenticated if a Bearer token (JWT) is provided
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"message": "Login successful"}
