from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime, timezone


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")

    isEmailVerified = Column(Boolean, default=False)

    # One to many relationship: One user can have many refresh tokens
    refresh_tokens = relationship("RefreshToken", back_populates="user")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id")
    )  # Foreign key constraint that enforces referential integrity (can't have a refresh token for a non-existent user)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at = Column(DateTime(timezone=True))
    # Used to manually invalidate refresh tokens
    is_revoked = Column(Boolean, default=False)

    # Many to one relationship: Many refresh tokens belong to one user
    user = relationship("User", back_populates="refresh_tokens")
