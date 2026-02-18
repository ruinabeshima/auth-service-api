# Project Management and Authentication API V1
[![Python Authentication API CI/CD](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml/badge.svg)](https://github.com/ruinabeshima/auth-service-api/actions/workflows/main.yml)

A backend service built with FastAPI to demonstrate authentication architecture using stateless JWT access tokens, refresh token rotation, RBAC, rate limiting, audit logging, and containerized cloud deployment.


## Tech Stack 
- **Framework**: FastAPI
- **Database**: PostgreSQL (Neon)
- **ORM**: SQLAlchemy
- **Migrations**: Alembic
- **Authentication**: JWT (python-jose)
- **Password Hashing**: bcrypt
- **Email**: Resend
- **Rate Limiting**: Redis 
- **Testing**: Pytest
- **Logging**: python-json-logger
- **Deployment**: Google Cloud Run
- **CI/CD**: GitHub Actions


## Architecture 
- The application is designed with scalability and modularity in mind. 
- The project is organized into clear modules (`api`, `core`, `services`, `models`, `schemas`) to separate concerns and make it easy to extend or refactor individual components.
- The API is stateless, enabling horizontal scaling (Redis).
- Production secrets are different from local variables, are stored in Github Secrets.
- Redis is used for rate limiting and can be scaled independently.
- Docker containerization allows easy deployment and scaling.
- Database indexes are chosen based on query patterns.
- Soft deletion of projects allows audit integrity
- Designed for Google Cloud Run, which auto-scales instances.


## Features
- **User Accounts** 
  - User registration 
  - User login 
  - Email verification 
  - Password reset by email 
  - Access tokens and refresh token rotation 
  - Logout
- **Projects** 
  - Create project 
  - View user projects 
  - View individual project by ID 
  - Edit project 
  - Delete project 
- **Admin Perks** 
  - View a paginated list of all users 
  - View a paginated list of all projects 
  - Update user roles 
- **Security**
  - Password hashing with bcrypt 
  - JWT token expiration 
  - Refresh token rotation 
  - Email verification requirement 
  - Role-based access control (RBAC)
  - Rate Limiting 
  - Prevention of cross-user data access
  - All sensitive operations are logged for audit purposes
- **Environment Variables** 
  - All `.env` variables are in `.env.example` 
  - Variables for production are configured in Github Secrets
  - See `.env.example` for all required environment variables
- **Developer Ease** 
  - Easy to read comments 
  - Consistent audit logging and structured logs 
  - Detailed commit messages 
  - Database migration history 
  - Locally hosted Postgres database, with production database configured to run on Neon
- **CICD** 
  - Runs tests and deploys to Google Cloud Run automatically
  - Unit tests and API tests. Test have an isolated test database setup
  - Docker containerisation: `docker-compose.yml` is used for local development, and `Dockerfile` is used for production builds.
  - Github actions
- **API Versioning**
  - `src/api/v1`


## Application Logic 

### Access Tokens 
1. Access tokens are used to authenticate requests to protected endpoints. 
2. JWT tokens are used as access tokens, which are short-lived. 
3. They are made up of the header, payload and signature. 
  - The HTTP request header contains `Authorization: Bearer: <access_token>` which is used to access protected routes. 
  - The payload contains encoded meta-information such as the expiration time of the token as well as username. 
4. They are stateless, which means no database lookup is involved, and are validated using a secret key. 

### Refresh Tokens 
1. Refresh tokens improve security by limiting how long access tokens remain valid while still allowing users to stay logged in.
2. Refresh tokens are long-lived tokens which are stored in a table in the database. Users have a one-to-many relationship with refresh tokens. 
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
2. All refresh tokens are revoked for a user. 
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

### Rate Limiting 
1. A fixed window counter algorithm is used with Redis as the backend. 
2. Each client has a unique key in Redis that tracks the number of requests within a set time window.
3. If the value exceeds the limit, error is returned.
4. A new window automatically resets the count.
5. The limit and window counter are taken in as parameters when utilised in routes. 
6. Supports both Upstash Redis REST for production and local Redis for deployment

### Pagination 
1. The routes `GET /admin/list` and `/projects` allow the page number and number of items per page to be taken in as parameters. 
2. Parameter validation ensures that suitable values are input.

### Projects 
1. Signed-in users can create a project, view them, update them and delete them. 
2. Ownership-based authorization is enforced at the service layer to prevent cross-user data access. Queries are scoped to the authenticated user unless the user has an admin role.
3. is_deleted ensures soft deletion instead of complete deletion; this preserves historical data and audit integrity. 
4. The database ensures a single user cannot have two projects with the same name.

### Audit Logs 
1. Audit logs are applied to: 
  - Authentication events
  - Role and permission changes 
  - Data modification actions (create, update, delete)
  - Authorization failures on protected operations
2. All event types are consistent to allow to easy querying in the database; ex. `UPDATE_PROJECT_SUCCESS`, `USER_LOGIN_FAILURE`.
3. If there is a reason for a failure, it is included in the `reason` column. 
4. Audit logs are intended for security monitoring and forensic tracability.

### Structured Logs 
1. Output in JSON format in the console. 
2. Intended for developers and operations monitoring. 
3. Example: 
  `{
    "timestamp": "2026-02-17T12:30:01Z",
    "level": "INFO",
    "event": "USER_LOGIN_SUCCESS",
    "user_id": 12,
    "ip_address": "192.168.1.10"
  }`


## API Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/me` | Protected route for all users | 
| GET | `/admin` | Admin-only protected route
| GET | `/admin/list` | Get list of all users (admin only) | 
| GET | `/projects` | Get list of projects (owner and admin only) | 
| GET | `/projects/{id}` | Get a singular project (owner and admin only) | 
| GET | `/health` | Confirm the database connection and that the API is running | 
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
- `audit_logs`: id, user_id, event_type, reason, ip_address, created_at
- `projects`: id, name, description, user_id, created_at, updated_at, is_deleted
- One to many relationship between users and refresh tokens, audit logs and projects

### Database Indexing 
- Several fields in each model were indexed for performance considerations. 
- Indexing speeds up data retrieval by creating optimised data structures containing that field only. 
- However, creating the index structures slows down writing to the database. 
- Keeping this in mind, only important fields were indexed. 


## Error Codes 
- 400: Invalid input 
- 401: Unauthorized: Missing or invalid access token
- 403: Forbidden; valid token, but user lacks permission
- 404: Not found; resource doesn't exist. 
- 422: Schema validation; unprocessable entity 
- 429: Too many requests
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