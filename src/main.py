from sqlalchemy.orm import Session
from fastapi import FastAPI, HTTPException, status, Depends

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from .database import Base, engine, get_db
from .models import User
from .email_service import send_password_reset_email

from .schemas import (
    RegisterUser,
    TokenData,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    SendResetEmailRequest,
)

from .auth import (
    hash_password,
    verify_access_token,
    verify_password,
    create_access_token,
    create_reset_token,
    verify_reset_token,
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Create the database tables
Base.metadata.create_all(bind=engine)


@app.get("/")
def main():
    return {"message": "Welcome to my Python Authentication API!"}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: RegisterUser, db: Session = Depends(get_db)):

    # Raise exception - username already exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )

    # Raise exception - email already exists
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
        )

    # Hash password
    hashed_password = hash_password(user.password)

    # Add user to database
    new_user = User(
        username=user.username, email=user.email, hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Return response object with no passwords for security
    return {
        "username": user.username,
        "message": "Register successful",
    }


@app.post("/login")
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):

    if "@" in form_data.username:
        # Get email from database
        db_user = db.query(User).filter(User.email == form_data.username).first()
    else:
        # Get username from database
        db_user = db.query(User).filter(User.username == form_data.username).first()

    # Raise exception - password does not match / user account doesn't exist
    if not db_user or not verify_password(
        form_data.password, str(db_user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            # WWW-Authenticate: Signals to the browser that user can be authenticated if a Bearer token (JWT) is provided
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate JWT Token once logged in
    token_info = TokenData(username=str(db_user.username))
    access_token = create_access_token(token_info)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me")
def get_user_page(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = verify_access_token(token)
    username = payload.get("sub")

    # Verify user exists in database
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    username = payload.get("sub")
    return {"message": f"Hello {username}, welcome to your page!"}


@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Verify email exists in database
    db_user = db.query(User).filter(User.email == request.email).first()

    if db_user:
        reset_token = create_reset_token(str(db_user.username))
        # Send reset email
        new_request = SendResetEmailRequest(
            to_email=str(db_user.email), reset_token=reset_token
        )
        send_password_reset_email(new_request)

        return {
            "message": "If the account exists, a reset link has been sent",
            "reset_token": reset_token,
        }

    return {"message": "If the account exists, a reset link has been sent"}


@app.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    # Verify the reset token
    decoded_payload = verify_reset_token(request.token)
    username = decoded_payload.get("sub")

    # Verify user exists in database
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update with new password
    db_user.hashed_password = hash_password(request.new_password)  # type: ignore
    db.commit()

    return {"message": "Password reset successful"}
