# Authentication Service API 
[![Python Authentication API CI/CD](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml/badge.svg)](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml)

A backend service built with FastAPI to demonstrate authentication, authorization, and backend engineering fundamentals.


## Features 
- **User Registration**: Secure signup with password hashing using bcrypt
- **JWT Authentication**: Stateless login issuing signed bearer tokens
- **Password Reset**: Secure password reset flow with email verification
- **Email Service**: Integrated with Resend for transactional emails
- **Protected Routes**: Restrict access to authorized users only
- **PostgreSQL Storage**: Persistent user account storage via Neon 


## Architecture / Flow

### Authentication Flow
1. Client sends credentials via `POST /login`
2. Server validates against the database and generates a JWT token
3. Client includes token in `Authorization: Bearer <token>` header
4. Protected routes verify the token before granting access

### Password Reset Flow
1. User requests reset via `POST /forgot-password` with their email
2. Server generates a short-lived reset token (5 minutes)
3. Email is sent with reset link containing the token
4. User submits new password via `POST /reset-password` with the token
5. Password is updated and user can login with new credentials


## API Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Create a new user account |
| POST | `/login` | Login and receive JWT access token |
| GET | `/me` | Get current user profile (protected) |
| POST | `/forgot-password` | Request password reset email |
| POST | `/reset-password` | Reset password with token |


## Error Codes 
- 400/401: Manual Exceptions 
- 422: Schema validation


## Getting Started

### Installation

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

- Run the app:
```bash
uvicorn src.main:app --reload
```