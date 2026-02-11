from sqlalchemy.orm import Session
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from .database import get_db
from .models import User
from .auth import verify_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(
    token=Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:

    try:
        # Verifies token
        payload = verify_access_token(token)
        username = payload.get("sub")

        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Retrieves user from database
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return db_user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin priviliges required"
        )
    return current_user
