from pydantic import BaseModel, Field, model_validator


class RegisterUser(BaseModel):
    # Username must be between 3 and 15 alphanumeric characters
    username: str = Field(min_length=3, max_length=15, pattern="^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=8, max_length=40)
    confirm_password: str

    # Raise exception - input passwords do not match
    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class LoginUser(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    username: str
