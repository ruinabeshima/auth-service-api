from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from schemas import RegisterUser, TokenData
from database import Base, engine, get_db
from sqlalchemy.orm import Session
from models import User
from auth import (
    hash_password,
    verify_access_token,
    verify_password,
    create_access_token,
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Create the database tables
Base.metadata.create_all(bind=engine)


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: RegisterUser, db: Session = Depends(get_db)):

    # Raise exception - username already exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
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

    # Add user to database
    new_user = User(username=user.username, hashed_password=hashed_password)
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

    # Get user from database
    db_user = db.query(User).filter(User.username == form_data.username).first()

    # Raise exception - password does not match / user account doesn't exist
    if not db_user or not verify_password(
        form_data.password, str(db_user.hashed_password)
    ):
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
