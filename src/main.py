from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi import FastAPI, HTTPException, status, Depends, Request, Query
from datetime import datetime, timezone

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from .database import get_db
from .models import User, RefreshToken, Project
from .email_service import send_password_reset_email, send_account_verification_email
from .authorization import get_current_user, require_admin
from .audit_logs import create_audit_log
from .redis import RateLimiter

from .schemas import (
    RegisterUser,
    TokenData,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    SendResetEmailRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserResponse,
    UpdateRoleRequest,
    SendVerificationEmailRequest,
    VerifyEmailRequest,
    PaginatedUsersResponse,
    CreateAuditLogRequest,
    CreateProject,
    ProjectResponse,
    PaginatedProjects,
    UpdateProject,
)

from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_reset_token,
    verify_reset_token,
    create_refresh_token,
    get_refresh_token_expiry,
    create_verification_token,
    verify_verification_token,
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@app.get("/")
def main():
    return {"message": "Welcome to my Python Authentication API!"}


@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(RateLimiter(limit=3, window_seconds=3600))
    ],  # Only 3 registrations per hour
)
def register_user(user: RegisterUser, request: Request, db: Session = Depends(get_db)):

    # Raise exception - username already exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="REGISTER FAILURE: Username already exists",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )

    # Raise exception - email already exists
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="REGISTER FAILURE: Email already exists",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
        )

    # Hash password
    hashed_password = hash_password(user.password)

    # Add user to database
    new_user = User(
        username=user.username, email=user.email, hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=new_user.id,  # type: ignore
        event_type="REGISTER SUCCESS: Verification email sent",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    # Send verification email
    verification_request = SendVerificationEmailRequest(
        to_email=str(user.email),
        verification_token=create_verification_token(str(user.username)),
    )
    send_account_verification_email(verification_request)

    # Return response object with no passwords for security
    return {
        "username": user.username,
        "message": "Register successful. Verification email has been sent to your account!",
    }


@app.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[
        Depends(RateLimiter(limit=5, window_seconds=60))
    ],  # Only 5 login attemps per minute
)
def login_user(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):

    if "@" in form_data.username:
        # Get email from database
        db_user = db.query(User).filter(User.email == form_data.username).first()
    else:
        # Get username from database
        db_user = db.query(User).filter(User.username == form_data.username).first()

    # Raise exception - password does not match / user account doesn't exist
    if not db_user or not verify_password(
        form_data.password, str(db_user.hashed_password)
    ):
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=db_user.id if db_user else None,  # type:ignore
            event_type="LOGIN FAILURE: Invalid credentials",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            # WWW-Authenticate: Signals to the browser that user can be authenticated if a Bearer token (JWT) is provided
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Raise exception - account is not verified
    if db_user.is_email_verified == False:  # type: ignore
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="LOGIN FAILURE: Account not verified",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not verified. Please check your email!",
        )

    # Generate JWT Token once logged in
    token_info = TokenData(username=str(db_user.username))
    access_token = create_access_token(token_info)

    # Generate refresh token
    refresh_token = create_refresh_token()

    # Store refresh token in database
    db_refresh_token = RefreshToken(
        token=refresh_token,
        user_id=db_user.id,  # type:ignore
        expires_at=get_refresh_token_expiry(),
    )
    db.add(db_refresh_token)
    db.commit()

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=db_user.id,  # type: ignore
        event_type="LOGIN SUCCESS: Access and refresh token obtained",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@app.post(
    "/forgot-password",
    dependencies=[
        Depends(RateLimiter(limit=3, window_seconds=3600))
    ],  # Only 3 attempts per hour
)
def forgot_password(
    request: Request, reset_data: ForgotPasswordRequest, db: Session = Depends(get_db)
):
    # Verify email exists in database
    db_user = db.query(User).filter(User.email == reset_data.email).first()

    if db_user:
        reset_token = create_reset_token(str(db_user.username))
        # Send reset email
        new_request = SendResetEmailRequest(
            to_email=str(db_user.email), reset_token=reset_token
        )
        send_password_reset_email(new_request)

        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=db_user.id,  # type: ignore
            event_type="EMAIL FORGOT PASSWORD SUCCESS: Email sent to reset password",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        return {
            "message": "If the account exists, a reset link has been sent",
            "reset_token": reset_token,
        }

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=None,
        event_type="EMAIL FORGOT PASSWORD FAILURE: Email does not exist",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {"message": "If the account exists, a reset link has been sent"}


@app.post(
    "/reset-password", dependencies=[Depends(RateLimiter(limit=3, window_seconds=3600))]
)
def reset_password(
    request: Request, reset_data: ResetPasswordRequest, db: Session = Depends(get_db)
):
    # Verify the reset token
    decoded_payload = verify_reset_token(reset_data.token)
    username = decoded_payload.get("sub")

    # Verify user exists in database
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="RESET PASSWORD FAILURE: User not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(status_code=404, detail="User not found")

    # Update with new password
    db_user.hashed_password = hash_password(reset_data.new_password)  # type: ignore
    db.commit()

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=db_user.id,  # type: ignore
        event_type="RESET PASSWORD SUCCESS: Password reset successfully",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {"message": "Password reset successful"}


@app.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[
        Depends(RateLimiter(limit=5, window_seconds=60))
    ],  # Prevent refresh token abuse
)
def refresh_token(
    request: Request, refresh_data: RefreshTokenRequest, db: Session = Depends(get_db)
):
    # Find refresh token in database
    db_refresh_token = (
        db.query(RefreshToken)
        .filter(RefreshToken.token == refresh_data.refresh_token)
        .first()
    )

    # Token doesn't exist
    if not db_refresh_token:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="REFRESH TOKEN FAILURE: Token does not exist",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    # Token is revoked
    if db_refresh_token.is_revoked:  # type:ignore
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=db_refresh_token.user_id,  # type: ignore
            event_type="REFRESH TOKEN FAILURE: Token is revoked",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Token has expired
    if db_refresh_token.expires_at < datetime.now(timezone.utc):  # type:ignore
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=db_refresh_token.user_id,  # type: ignore
            event_type="REFRESH TOKEN FAILURE: Token has expired",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        db.delete(db_refresh_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )

    # Get user from database if refresh token is valid
    db_user = db.query(User).filter(User.id == db_refresh_token.user_id).first()
    if not db_user:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="REFRESH TOKEN FAILURE: User not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Generate new access token
    new_token = TokenData(username=str(db_user.username))
    new_access_token = create_access_token(new_token)

    # Revoke old refresh token and generate new token for rotation
    new_refresh_token = create_refresh_token()
    db_refresh_token.is_revoked = True  # type:ignore

    # Store new refresh token
    new_db_refresh_token = RefreshToken(
        token=new_refresh_token,
        user_id=db_user.id,
        expires_at=get_refresh_token_expiry(),
    )
    db.add(new_db_refresh_token)
    db.commit()

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=db_user.id,  # type: ignore
        event_type="REFRESH TOKEN SUCCESS: New access token generated and refresh token rotated",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


@app.post("/logout")
def logout_user(
    request: Request, logout_request: RefreshTokenRequest, db: Session = Depends(get_db)
):
    # Get refresh token and revoke
    db_refresh_token = (
        db.query(RefreshToken)
        .filter(RefreshToken.token == logout_request.refresh_token)
        .first()
    )

    if db_refresh_token:
        db_refresh_token.is_revoked = True  # type:ignore
        db.commit()

        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=db_refresh_token.user_id,  # type: ignore
            event_type="LOGOUT SUCCESS: User logged out",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

    if not db_refresh_token:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="LOGOUT FAILURE: Refresh token not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

    return {"message": "Logout successful"}


@app.get("/me", response_model=UserResponse)
def get_user_page(current_user=Depends(get_current_user)):
    return current_user


@app.get("/admin", response_model=UserResponse)
def get_admin_page(admin_user=Depends(require_admin)):
    return admin_user


@app.get("/admin/list", response_model=PaginatedUsersResponse)
def get_admin_list(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
    # Query parameters with validation
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    users_count = db.query(User).count()

    # Offset: Starting index for the database query
    users = db.query(User).offset((page - 1) * page_size).limit(page_size).all()

    response = PaginatedUsersResponse(
        total=users_count, page=page, page_size=page_size, users=users  # type: ignore
    )
    return response


@app.patch("/admin/update_role", response_model=UserResponse)
def update_user_role(
    request: Request,
    update_role_request: UpdateRoleRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    # Retrieve user from database
    target_user = (
        db.query(User).filter(User.username == update_role_request.username).first()
    )
    if not target_user:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="UPDATE ROLE FAILURE: Target user not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update role to admin
    target_user.role = update_role_request.role  # type: ignore
    db.commit()
    db.refresh(target_user)

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=target_user.id,  # type: ignore
        event_type="UPDATE_ROLE_SUCCESS: Role updated successfully",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return target_user


@app.post(
    "/verify-account",
    dependencies=[
        Depends(
            RateLimiter(
                limit=5, window_seconds=60
            )  # Prevent account verification abuse
        )
    ],
)
def verify_account(
    request: Request,
    verify_request: VerifyEmailRequest,
    db: Session = Depends(get_db),
):
    # Verify the verification token
    decoded_payload = verify_verification_token(verify_request.token)
    username = decoded_payload.get("sub")

    # Verify user exists in database
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=None,
            event_type="VERIFY ACCOUNT FAILURE: User not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(status_code=404, detail="User not found")

    # Update isEmailVerified
    db_user.is_email_verified = True  # type: ignore
    db.commit()

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=db_user.id,  # type: ignore
        event_type="VERIFY ACCOUNT SUCCESS: Account verified",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {"message": "Account verification successful"}


@app.get("/projects", response_model=PaginatedProjects)
def get_user_projects(
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    # Query parameters with validation
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
):
    projects_count = (
        db.query(Project)
        .filter(Project.user_id == user.id, Project.is_deleted == False)
        .count()
    )
    projects = (
        db.query(Project)
        .filter(Project.user_id == user.id, Project.is_deleted == False)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .order_by(Project.created_at.desc())
        .all()
    )

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=user.id,
        event_type=f"GET PROJECT SUCCESS: Page {page} of projects shown",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {
        "total": projects_count,
        "page": page,
        "page_size": page_size,
        "projects": projects,
    }


@app.get("/projects/{id}", response_model=ProjectResponse)
def get_project_by_id(
    id: int,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    project = (
        db.query(Project).filter(Project.id == id, Project.is_deleted == False).first()
    )

    if not project:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="GET PROJECT BY ID FAILURE: Project not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )

    if project.user_id != user.id and user.role != "admin":
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="GET PROJECT BY ID FAILURE: Not authorised to view project",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this project",
        )

    return project


@app.post("/projects/add", response_model=ProjectResponse)
def create_new_project(
    request: Request,
    project_data: CreateProject,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_project = Project(
        name=project_data.name, description=project_data.description, user_id=user.id
    )

    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=user.id,
        event_type="CREATE PROJECT SUCCESS: Project created",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return new_project


@app.patch("/projects/{id}", response_model=ProjectResponse)
def update_project(
    id: int,
    request: Request,
    project_update: UpdateProject,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Get already existing project
    project = db.query(Project).filter(Project.id == id).first()

    if not project:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="UPDATE PROJECT FAILURE:  Project not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )

    if project.user_id != user.id and user.role != "admin":  # type: ignore
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="UPDATE PROJECT FAILURE: Not allowed to update project",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to update this project",
        )

    if project.is_deleted:  # type: ignore
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="UPDATE PROJECT FAILURE:  Project has been deleted",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project has been deleted",
        )

    # Partial Updates
    if project_update.name is not None:
        project.name = project_update.name  # type: ignore
    if project_update.description is not None:
        project.description = project_update.description  # type: ignore
    db.commit()
    db.refresh(project)

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=user.id,
        event_type="UPDATE PROJECT SUCCESS: Project has been updated",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return project


@app.delete("/projects/{id}")
def delete_project(
    id: int,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Get already existing project
    project = db.query(Project).filter(Project.id == id).first()

    if not project:
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="DELETE PROJECT FAILURE:  Project not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )

    if project.user_id != user.id and user.role != "admin":  # type: ignore
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="DELETE PROJECT FAILURE: Not allowed to delete project",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this project",
        )

    if project.is_deleted:  # type: ignore
        # Add audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="DELETE PROJECT FAILURE:  Project has been deleted already",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project has been deleted already",
        )

    project.is_deleted = True  # type: ignore
    db.commit()
    db.refresh(project)

    # Add audit log
    log_data = CreateAuditLogRequest(
        user_id=user.id,
        event_type="DELETE PROJECT SUCCESS: Project has been deleted successfully",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {"message": "Project has been successfully deleted"}


@app.get("/health")
def health_check(
    db: Session = Depends(get_db),
):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception:
        return {"status": "error", "database": "disconnected"}
