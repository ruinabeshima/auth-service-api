from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import bcrypt


# User model
class User(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str


# Helper function for hashing passwords
def hash_password(password: str):
    # Convert plain text password to bytes
    password_bytes = password.encode("utf-8")
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password using the salt
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    # Convert resulting bytes back to a string for easy storage
    return hashed_password.decode("utf-8")


app = FastAPI()


@app.post("/register", status_code=status.HTTP_201_CREATED)
def RegisterUser(user: User):

    # Raise exception - passwords do not match
    if user.password != user.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match"
        )

    # Hash password
    hashed_password = hash_password(user.password)

    # Return response object with no passwords for security
    return {"username": user.username, "email": user.email, "password": hashed_password}
