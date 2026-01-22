from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
import os
from dotenv import load_dotenv
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

load_dotenv()
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Environment variables
secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")
algorithm = os.getenv("ALGORITHM", "HS256")
expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))

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


class TokenData(BaseModel):
    username: str


# Helper function for creating JWT token
def create_access_token(token_data: TokenData):
    expiration_time = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)

    # JWT info: standard JSON data
    payload = {
        "sub": token_data.username,
        "exp": expiration_time,
        "iat": datetime.now(timezone.utc),
    }

    # Generate signature using payload and secret key
    encoded_jwt = jwt.encode(payload, secret_key, algorithm=algorithm)

    # Returns JWT token: Header + Payload + Signature
    return encoded_jwt


# Helper function for verifying JWT token
def verify_access_token(token: str):
    try:
        decoded_payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return decoded_payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        )


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


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: RegisterUser):

    # Raise exception - username already exists
    # TEMPORARY
    if user.username in users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )

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
def login_user(form_data: OAuth2PasswordRequestForm = Depends()):

    # TEMPORARY: Get user from dictionary
    hashed_password = users.get(form_data.username)

    # Raise exception - password does not match / user account doesn't exist
    if not hashed_password or not verify_password(form_data.password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            # WWW-Authenticate: Signals to the browser that user can be authenticated if a Bearer token (JWT) is provided
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate JWT Token once logged in
    token_info = TokenData(username=form_data.username)
    access_token = create_access_token(token_info)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me")
def get_user_page(token: str = Depends(oauth2_scheme)):
    payload = verify_access_token(token)
    username = payload.get("sub")
    return {"message": f"Hello {username}, welcome to your page!"}
