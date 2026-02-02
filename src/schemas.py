from pydantic import BaseModel, Field


class RegisterUser(BaseModel):
    # Username must be between 3 and 15 alphanumeric characters
    username: str = Field(min_length=3, max_length=15, pattern="^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=8, max_length=40)
    confirm_password: str


class LoginUser(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    username: str
