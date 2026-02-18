from fastapi import HTTPException, status
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

from src.models import User, RefreshToken
from src.core.email_service import (
    send_password_reset_email,
    send_account_verification_email,
)

from .audit_service import create_audit_log

from src.schemas import (
    TokenData,
    SendResetEmailRequest,
    SendVerificationEmailRequest,
    CreateAuditLogRequest,
)

from src.core.security import (
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


def register(user, request, db):

    logger.info(
        "Registration attempt",
        extra={"username": user.username, "email": user.email},
    )

    # Raise exception - username already exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        logger.warning(
            "Registration failed - username already exists",
            extra={"username": user.username},
        )

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
        logger.warning(
            "Registration failed - email already exists", extra={"email": user.email}
        )

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
    logger.info("Password hashed for new user", extra={"username": user.username})

    # Add user to database
    new_user = User(
        username=user.username, email=user.email, hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(
        "User successfully created",
        extra={"user_id": new_user.id, "username": user.username},
    )

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


def login(request, form_data, db):
    logger.info("Login attempt", extra={"username": form_data.username})

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
        logger.warning(
            "Login failed - invalid credentials", extra={"username": form_data.username}
        )

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
        logger.warning(
            "Login failed - account not verified",
            extra={"username": form_data.username},
        )

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

    logger.info(
        "Login successful - tokens issued",
        extra={"username": db_user.username},
    )

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


def forgot_password(request, reset_data, db):
    logger.info("Password reset requested", extra={"username": reset_data.email})

    # Verify email exists in database
    db_user = db.query(User).filter(User.email == reset_data.email).first()

    if db_user:
        reset_token = create_reset_token(str(db_user.username))
        # Send reset email
        new_request = SendResetEmailRequest(
            to_email=str(db_user.email), reset_token=reset_token
        )
        send_password_reset_email(new_request)

        logger.info(
            "Password reset email sent",
            extra={"user_id": db_user.id},
        )

        log_data = CreateAuditLogRequest(
            user_id=db_user.id,  # type: ignore
            event_type="EMAIL FORGOT PASSWORD SUCCESS: Email sent to reset password",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        return {
            "message": "If the account exists, a reset link has been sent",
            # TODO: REMOVE IN PRODUCTION
            "reset_token": reset_token,
        }

    logger.warning(
        "Password reset requested for non-existent account",
        extra={"username": reset_data.email},
    )

    log_data = CreateAuditLogRequest(
        user_id=None,
        event_type="EMAIL FORGOT PASSWORD FAILURE: Email does not exist",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {"message": "If the account exists, a reset link has been sent"}


def reset_password(request, reset_data, db):
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


def refresh(request, refresh_data, db):
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


def logout(request, logout_request, db):
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


def verify(request, verify_request, db):
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
