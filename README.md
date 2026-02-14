# Project Management and Authentication API 
[![Python Authentication API CI/CD](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml/badge.svg)](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml)

A backend service built with FastAPI to demonstrate authentication, authorization, and backend engineering fundamentals.


## Tech Stack 
- **Framework**: FastAPI
- **Database**: PostgreSQL (Neon)
- **ORM**: SQLAlchemy
- **Migrations**: Alembic
- **Authentication**: JWT (python-jose)
- **Password Hashing**: bcrypt
- **Email**: Resend
- **Testing**: Pytest
- **Deployment**: Google Cloud Run
- **CI/CD**: GitHub Actions

## Features 
- **Projects**: Signed-in users can create their own projects, view a list of their projects, view a single project, update their project and delete their projects. 
- **User Registration**: Secure signup with password hashing using bcrypt
- **JWT Authentication**: Stateless login issuing signed bearer tokens
- **Password Reset**: Secure password reset flow with email verification
- **Email Service**: Integrated with Resend for transactional emails
- **Protected Routes**: Restrict access to authorized users only
- **PostgreSQL Storage**: Persistent user account storage via Neon
- **Tests**: Unit tests and API tests implemented using Pytest
- **Deployment**: CI/CD through Github Actions, and deployment on Google Cloud Run 
- **Audit Logs**: Logging of all event types in the table `audit_logs`. Each log entry includes the user (if available), event type, IP address, and timestamp for security and traceability.

## Security Features 
- Password hashing with bcrypt 
- JWT token expiration 
- Refresh token rotation 
- Email verification requirement 
- Role-based access control (RBAC)


## Logic of the Application 

### Access Tokens 
1. Access tokens are used to authenticate requests to protected endpoints. 
2. JWT tokens are used as access tokens, which are short-lived. 
3. They are made up of the header, payload and signature. 
  - The header contains `Authorization: Bearer: <access_token>` which is used to access protected routes. 
  - The payload contains encoded meta-information such as the expiration time of the token as well as username. 
4. They are stateless, which means no database lookup is involved, and are validated using a secret key. 

### Refresh Tokens 
1. Refresh tokens improve security by limiting how long access tokens remain valid while still allowing users to stay logged in.
2. . Refresh tokens are long-lived tokens which are stored in a table in the database. Users have a one-to-many relationship with refresh tokens. 
3. They are used to generate new access tokens when the old access token expires, through the `POST /refresh` route. 
4. Once a new access token is generated, the refresh token is revoked and a new one is generated. This is refresh token rotation. 
5. The refresh token is also revoked and deleted from the database if expired, which means the user must log in again.  
6. For the `POST /logout` route, the user's refresh token is revoked. 

### Register 
1. User creates an account through the `POST /register` route. 
2. Username, email and password is taken in as input. 
3. Password is hashed before storing in the database. 
4. A verification email is sent to the user's email. 
  - Users cannot login if their account is not verified. 
5. A success message is returned confirming registration and email verification 

### Login 
1. User must have a verified account to login successfully. 
2. User can login through the `POST /login` route. 
3. Username and password is taken as input; the user's email can be input in place of username if required. 
4. Credentials are verified through the database. 
5. If login is successful, an access token and refresh token is generated and returned. Refresh token is stored in the database

### Logout 
1. In the `POST /logout` route, the user's refresh token is revoked.
2. All refresh tokens are revoked for a suser. 
2. This means logging out of one device logs the user out of everywhere.

### Password Reset
1. If the user forgets their password during login, the `POST /forgot-password` route is accessed. 
2. A reset token is generated and sent to the function `send_password_reset_email`, which sends a reset email to the user's account. 
3. The user is given a link with the endpoint `/reset-password?token={reset_token}`.
4. The route `POST /reset-password` is accessed with the user's new password. 
5. The reset token is verified and the database is updated with the user's new password

### Account Verification 
1. The function `send_account_verification_email` sends a verification email to the users email. 
2. A verification token is generated beforehand. 
3. The user receives a link with the endpoint `/verify-account?token={verification_token}`.
4. The route `POST /verify-account` is accessed. 
5. The user's verification token is verified and the users `is_email_verified` is updated in the database. 

### User Roles 
1. An account may have a default 'user' role or an 'admin' role. 
2. All users can access the `GET /me` route, but only admins can access the `GET /admin` route. 
3. The route `GET /admin/list` allows admins to obtain a list of all users, their emails and their roles. This page is paginated through an `offset`.
4. Already existing admins can use the route `PATCH /admin/update_role` to update users to admin role, and vice versa. 
5. There is no way for a default user to promote themselves to admin; by using `create_admin.py`, a user can be manually changed to an admin. Run: 
```bash
python create_admin.py <username>
```

### Projects 
1. Signed-in users can create a project, view them, update them and delete them. 
2. Only the owners of the project and admins can interact with the project. 


## API Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/me` | Protected route for all users | 
| GET | `/admin` | Admin-only protected route
| GET | `/admin/list` | Get list of all users (admin only) | 
| GET | `/projects` | Get list of projects (owner and admin only) | 
| GET | `/projects/{id}` | Get a singular project (owner and admin only) | 
| POST | `/register` | Create a new user account |
| POST | `/login` | Login and receive access and refresh tokens |
| POST | `/forgot-password` | Request password reset email |
| POST | `/reset-password` | Reset password with token |
| POST | `/refresh` | Get new access token using existing refresh token | 
| POST | `/logout` | Revoke refresh token and logout | 
| POST | `/verify-account` | Verify email address with verification token| 
| POST | `/projects/add` | Create new project | 
| PATCH | `/admin/update_role` | Update user role (admin only) | 
| PATCH | `/projects/{id}` | Update project (owner and admin only) |
| DELETE | `/projects/{id}` | Delete project (owner and admin only) |  


## Database Models 
- `users`: id, username, email, hashed_password, role, is_email_verified 
- `refresh_tokens`: id, token, user_id, created_at, expires_at, is_revoked
- `audit_logs`: id, user_id, event_type, ip_address, created_at
- `projects`: id, name, description, user_id, created_at, updated_at, is_deleted
- One to many relationship between users and refresh tokens, audit logs and projects


## Error Codes 
- 400: Invalid input 
- 401: Unauthorized: Missing or invalid access token
- 403: Forbidden; valid token, but user lacks permission
- 404: Not found; resource doesn't exist. 
- 422: Schema validation; unprocessable entity 
- 500: Internal Server Error


## Getting Started
The API documentation is automatically generated and available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

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

- Start databases 
```bash
docker-compose up -d
```

- Run migrations 
```bash
alembic upgrade head
```

- Run the app:
```bash
uvicorn src.main:app --reload
```


### Run Tests 
```bash 
python -m pytest
```