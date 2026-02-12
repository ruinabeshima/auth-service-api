from .schemas import TokenData
from fastapi import HTTPException, status
import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import secrets

load_dotenv()

# Environment variables
secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")
algorithm = os.getenv("ALGORITHM", "HS256")
access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
reset_token_expire_minutes = int(os.getenv("RESET_TOKEN_EXPIRE_MINUTES", 5))
refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
verification_token_expire_minutes = int(
    os.getenv("VERIFICATION_TOKEN_EXPIRE_MINUTES", 7)
)


# Helper function for creating JWT token
def create_access_token(token_data: TokenData):
    expiration_time = datetime.now(timezone.utc) + timedelta(
        minutes=access_token_expire_minutes
    )

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


# Helper function to create a verification token for forgotten passwords
def create_reset_token(username: str):
    expiration_time = datetime.now(timezone.utc) + timedelta(
        minutes=reset_token_expire_minutes
    )

    payload = {"sub": username, "exp": expiration_time, "type": "password-reset"}

    encoded_jwt = jwt.encode(payload, secret_key, algorithm=algorithm)
    return encoded_jwt


def verify_reset_token(token: str):
    try:
        decoded_payload = jwt.decode(token, secret_key, algorithms=[algorithm])

        if decoded_payload.get("type") != "password-reset":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid reset token",
            )

        return decoded_payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Reset token has expired",
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


# Helper function to create a new refresh token
def create_refresh_token():
    # Generate random URL-safe string of 32 characters
    return secrets.token_urlsafe(32)


# Helper function to return expiry date of refresh token
def get_refresh_token_expiry():
    return datetime.now(timezone.utc) + timedelta(days=refresh_token_expire_days)


def create_verification_token(username: str):
    expiration_time = datetime.now(timezone.utc) + timedelta(
        minutes=verification_token_expire_minutes
    )

    payload = {"sub": username, "exp": expiration_time, "type": "account-verification"}

    encoded_jwt = jwt.encode(payload, secret_key, algorithm=algorithm)
    return encoded_jwt


def verify_verification_token(token: str):
    try:
        decoded_payload = jwt.decode(token, secret_key, algorithms=[algorithm])

        if decoded_payload.get("type") != "account-verification":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid verification token",
            )

        return decoded_payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Verification token has expired",
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
