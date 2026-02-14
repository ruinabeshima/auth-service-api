from pydantic import BaseModel, Field, model_validator, ConfigDict
from datetime import datetime
from typing import List


class RegisterUser(BaseModel):
    # Username must be between 3 and 15 alphanumeric characters
    username: str = Field(min_length=3, max_length=15, pattern="^[a-zA-Z0-9_]+$")
    email: str = Field(pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    password: str = Field(min_length=8, max_length=40)
    confirm_password: str

    # Raise exception - input passwords do not match
    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class LoginUser(BaseModel):
    identifier: str
    password: str


class TokenData(BaseModel):
    username: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str

    # Raise exception - input passwords do not match
    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class SendResetEmailRequest(BaseModel):
    to_email: str
    reset_token: str


class SendVerificationEmailRequest(BaseModel):
    to_email: str
    verification_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    # Enables Pydantic to read from SQLAlchemy models (Database objects) instead of only dictionaries
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str


class UpdateRoleRequest(BaseModel):
    username: str
    role: str = Field(pattern="^(user|admin)$")  # Role must be user or admin


class PaginatedUsersResponse(BaseModel):
    total: int
    page: int
    page_size: int
    users: List[UserResponse]


class CreateAuditLogRequest(BaseModel):
    user_id: int | None = None
    event_type: str


class CreateProject(BaseModel):
    name: str
    description: str


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    user_id: int


class PaginatedProjects(BaseModel):
    total: int
    page: int
    page_size: int
    projects: List[ProjectResponse]
