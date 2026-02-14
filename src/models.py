from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, Text, UniqueConstraint
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

    is_email_verified = Column(Boolean, default=False)

    # One to many relationship: One user can have many refresh tokens
    refresh_tokens = relationship("RefreshToken", back_populates="user")
    audit_logs = relationship("AuditLogs", back_populates="user")
    projects = relationship("Project", back_populates="user")


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


class AuditLogs(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    event_type = Column(String)
    ip_address = Column(String)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="audit_logs")


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=None,
        nullable=True,
        onupdate=lambda: datetime.now(timezone.utc),
    )

    is_deleted = Column(Boolean, default=False, index=True)

    user = relationship("User", back_populates="projects")

    # Constraint: One user cannot have two projects with the same name, but different users can have projects with the same name
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_user_project_name"),
    )
