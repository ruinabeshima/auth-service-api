# Authentication Service API 
A backend service built with FastAPI to demonstrate authentication, authorization, and backend engineering fundamentals.


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


## How to use this project (MacOS)
- Create a virtual environment:
```bash
python3 -m venv venv
```

- Activate the virtual environment:
```bash
source venv/bin/activate
```

- Install dependencies:
```bash
pip3 install -r requirements.txt
```

- Run the app (from the src directory):
```bash
uvicorn main:app --reload
```
