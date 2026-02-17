from fastapi import HTTPException, status
from src.models import User
from src.schemas import PaginatedUsersResponse, CreateAuditLogRequest
from .audit_service import create_audit_log

# ...existing code...


def get_admin_page(admin_user):
    return admin_user


def get_admin_list(db, admin_user, page, page_size):
    users_count = db.query(User).count()

    # Offset: Starting index for the database query
    users = db.query(User).offset((page - 1) * page_size).limit(page_size).all()

    response = PaginatedUsersResponse(
        total=users_count, page=page, page_size=page_size, users=users  # type: ignore
    )
    return response


def update_role(request, update_role_request, db, admin_user):
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
