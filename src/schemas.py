from pydantic import BaseModel


# User models
class RegisterUser(BaseModel):
    username: str
    password: str
    confirm_password: str


class LoginUser(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    username: str
