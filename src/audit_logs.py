from .models import AuditLogs
from .schemas import CreateAuditLogRequest
from .database import get_db
from sqlalchemy.orm import Session
from fastapi import Request, Depends


# Helper function to create a new audit log and add to database
def create_audit_log(
    request: Request, log_data: CreateAuditLogRequest, db: Session = Depends(get_db)
):
    new_audit_log = AuditLogs(
        user_id=log_data.user_id,
        event_type=log_data.event_type,
        # IP Address accessed using client object
        ip_address=request.client.host if request.client else "Unknown",
    )

    db.add(new_audit_log)
    db.commit()
    db.refresh(new_audit_log)

    return new_audit_log
