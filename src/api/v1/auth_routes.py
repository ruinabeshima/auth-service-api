from sqlalchemy.orm import Session
from fastapi import APIRouter, status, Depends, Request
from src.database import get_db
from src.core.redis import RateLimiter
from src.schemas import RegisterUser, TokenResponse, ForgotPasswordRequest, ResetPasswordRequest, RefreshTokenRequest, VerifyEmailRequest
from src.services import auth_service
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(RateLimiter(limit=3, window_seconds=3600))
    ],  # Only 3 registrations per hour
)
def register_user(user: RegisterUser, request: Request, db: Session = Depends(get_db)):
    return auth_service.register(user, request, db)


@router.post(
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
    return auth_service.login(request, form_data, db)


@router.post(
    "/forgot-password",
    dependencies=[
        Depends(RateLimiter(limit=3, window_seconds=3600))
    ],  # Only 3 attempts per hour
)
def forgot_password(
    request: Request, reset_data: ForgotPasswordRequest, db: Session = Depends(get_db)
):
    return auth_service.forgot_password(request, reset_data, db)


@router.post(
    "/reset-password", dependencies=[Depends(RateLimiter(limit=3, window_seconds=3600))]
)
def reset_password(
    request: Request, reset_data: ResetPasswordRequest, db: Session = Depends(get_db)
):
    return auth_service.reset_password(request, reset_data, db)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[
        Depends(RateLimiter(limit=5, window_seconds=60))
    ],  # Prevent refresh token abuse
)
def refresh_token(
    request: Request, refresh_data: RefreshTokenRequest, db: Session = Depends(get_db)
):
    return auth_service.refresh(request, refresh_data, db)


@router.post("/logout")
def logout_user(
    request: Request, logout_request: RefreshTokenRequest, db: Session = Depends(get_db)
):
    return auth_service.logout(request, logout_request, db)


@router.post(
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
    return auth_service.verify(request, verify_request, db)