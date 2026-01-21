from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel


# User model
class User(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str


app = FastAPI()


@app.post("/register", status_code=status.HTTP_201_CREATED)
def RegisterUser(user: User):

    # Raise exception - passwords do not match
    if user.password != user.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match"
        )

    # Return response object with no passwords for security
    return {"username": user.username, "email": user.email}
