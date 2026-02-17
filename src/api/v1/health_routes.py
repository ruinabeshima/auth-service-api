from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi import APIRouter, Depends
from src.database import get_db
from src.api.dependencies import get_current_user
from src.schemas import UserResponse

router = APIRouter()


@router.get("/")
def main():
    return {"message": "Welcome to my Python Authentication API!"}


@router.get("/me", response_model=UserResponse)
def get_user_page(current_user=Depends(get_current_user)):
    return current_user


@router.get("/health")
def health_check(
    db: Session = Depends(get_db),
):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception:
        return {"status": "error", "database": "disconnected"}
