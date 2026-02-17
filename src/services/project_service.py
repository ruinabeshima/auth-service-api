from fastapi import HTTPException, status
from src.models import Project
from .audit_service import create_audit_log
from src.schemas import CreateAuditLogRequest


def get_project(request, user, db, page, page_size):
    projects_count = (
        db.query(Project)
        .filter(Project.user_id == user.id, Project.is_deleted == False)
        .count()
    )

    projects = (
        db.query(Project)
        .filter(Project.user_id == user.id, Project.is_deleted == False)
        .order_by(Project.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
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


def get_project_by_id(id, request, user, db):
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


def add_project(request, project_data, user, db):
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


def update_project(id, request, project_update, user, db):
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


def delete_project(id, request, user, db):
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
