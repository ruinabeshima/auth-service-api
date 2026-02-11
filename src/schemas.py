from pydantic import BaseModel, Field, model_validator
from datetime import datetime


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


class TokenResponse(BaseModel):
    access_token: str 
    refresh_token: str 
    token_type: str