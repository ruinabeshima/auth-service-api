# Authentication Service API 
[![Python Authentication API CI/CD](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml/badge.svg)](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml)
- A backend service built with FastAPI to demonstrate authentication, authorization, and backend engineering fundamentals.


## Features 
- User Registration: Secure signup with password hashing, using bcrypt.
- JWT Authentication: Stateless login issuing signed bearer tokens.
- Protected route to restrict access to authorised users.
- Persistent storage of user accounts.


## Architecture / Flow 
- Client sends credentials via POST /login.
- Server validates against the database and generates a JWT token.
- When accessing the protected route /me, the client receives and verifies the JWT token. 


## API Routes
| Method | Endpoint | Description |
|---|---|---|
| POST | /register | Create a new user |
| POST | /login | Login user and receive JWT token |
| GET | /me | Get current user profile |


## Error Codes 
- 400/401: Manual Exceptions 
- 422: Schema validation 


## How to use this project
- Create a virtual environment:
```bash
python -m venv venv
```

- Activate the virtual environment:
```bash
source venv/bin/activate
```

- Install dependencies:
```bash
pip install -r requirements.txt
```

- Run the app (from the src directory):
```bash
uvicorn main:app --reload
```

- Run tests (from the root directory):
```bash
python -m pytest
```
