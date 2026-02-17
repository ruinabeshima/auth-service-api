from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, Request, Query
from src.database import get_db
from src.models import User
from src.api.dependencies import require_admin
from src.services import admin_service
from src.schemas import UserResponse, UpdateRoleRequest, PaginatedUsersResponse


router = APIRouter()


@router.get("/admin", response_model=UserResponse)
def get_admin_page(admin_user=Depends(require_admin)):
    return admin_service.get_admin_page(admin_user)


@router.get("/admin/list", response_model=PaginatedUsersResponse)
def get_admin_list(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
    # Query parameters with validation
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    return admin_service.get_admin_list(db, admin_user, page, page_size)


@router.patch("/admin/update_role", response_model=UserResponse)
def update_user_role(
    request: Request,
    update_role_request: UpdateRoleRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    return admin_service.update_role(request, update_role_request, db, admin_user)
