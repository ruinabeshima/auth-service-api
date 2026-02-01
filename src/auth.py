from schemas import TokenData
from fastapi import HTTPException, status
import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os

load_dotenv()

# Environment variables
secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")
algorithm = os.getenv("ALGORITHM", "HS256")
expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))


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
