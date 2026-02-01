from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from schemas import RegisterUser, TokenData
from auth import (
    hash_password,
    verify_access_token,
    verify_password,
    create_access_token,
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# TEMPORARY: User dictionary
users = {}


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
