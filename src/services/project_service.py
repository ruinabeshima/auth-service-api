from fastapi import HTTPException, status
from src.models import Project
from .audit_service import create_audit_log
from src.schemas import CreateAuditLogRequest
import logging

logger = logging.getLogger(__name__)


def get_project(request, user, db, page, page_size):
    # Logging
    logger.info("Get project request", extra={"user_id": user.id})

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

    # Logging
    logger.info(
        f"Get project success - Projects shown",
        extra={"user_id": user.id, "page": page, "page_size": page_size},
    )

    return {
        "total": projects_count,
        "page": page,
        "page_size": page_size,
        "projects": projects,
    }


def get_project_by_id(id, request, user, db):
    # Logging
    logger.info("Get project by ID request", extra={"user_id": user.id})

    project = (
        db.query(Project).filter(Project.id == id, Project.is_deleted == False).first()
    )

    if not project:
        # Logging
        logger.warning(
            "Get project by id failure - Project does not exist",
            extra={"user_id": user.id},
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )

    if project.user_id != user.id and user.role != "admin":
        # Logging
        logger.warning(
            "Get project by id failure - not authorized to view project",
            extra={"user_id": user.id},
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this project",
        )

    # Logging
    logger.info(
        "Get projecy by id success - project shown",
        extra={"user_id": user.id, "project_id": project.id},
    )

    return project


def add_project(request, project_data, user, db):
    # Logging
    logger.info("Add project request", extra={"user_id": user.id})

    new_project = Project(
        name=project_data.name, description=project_data.description, user_id=user.id
    )

    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    # Logging
    logger.info(
        "Get project success - project created",
        extra={"user_id": user.id, "project_id": new_project.id},
    )

    # Audit log
    log_data = CreateAuditLogRequest(
        user_id=user.id,
        event_type="CREATE_PROJECT_SUCCESS",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return new_project


def update_project(id, request, project_update, user, db):
    # Logging
    logger.info("Update project request", extra={"user_id": user.id})

    # Get already existing project
    project = db.query(Project).filter(Project.id == id).first()

    if not project:
        # Logging
        logger.warning(
            "Update project failure - project not found", extra={"user_id": user.id}
        )

        # Audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="UPDATE_PROJECT_FAILURE",
            reason="Project not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )

    if project.user_id != user.id and user.role != "admin":  # type: ignore
        # Logging
        logger.warning(
            "Update project failure - unauthorized", extra={"user_id": user.id}
        )

        # Audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="UPDATE_PROJECT_FAILURE",
            reason="Not allowed to update project",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to update this project",
        )

    if project.is_deleted:  # type: ignore
        # Logging
        logger.warning(
            "Update project failure - project deleted", extra={"user_id": user.id}
        )

        # Audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="UPDATE_PROJECT_FAILURE",
            reason="Project has been deleted",
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

    # Logging
    logger.info(
        "Update project success - project updated",
        extra={"user_id": user.id, "project_id": project.id},
    )

    # Audit log
    log_data = CreateAuditLogRequest(
        user_id=user.id,
        event_type="UPDATE_PROJECT_SUCCESS",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return project


def delete_project(id, request, user, db):
    # Logging
    logger.info("Delete project request", extra={"user_id": user.id})

    # Get already existing project
    project = db.query(Project).filter(Project.id == id).first()

    if not project:
        # Logging
        logger.warning(
            "Delete project failure - Project not found", extra={"user_id": user.id}
        )

        # Audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="DELETE_PROJECT_FAILURE",
            reason="Project not found",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )

    if project.user_id != user.id and user.role != "admin":  # type: ignore
        # Logging
        logger.warning(
            "Delete project failure - unauthorized", extra={"user_id": user.id}
        )

        # Audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="DELETE_PROJECT_FAILURE",
            reason="Not allowed to delete project",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to delete this project",
        )

    if project.is_deleted:  # type: ignore
        # Logging
        logger.warning(
            "Delete project failure - project deleted already",
            extra={"user_id": user.id},
        )

        # Audit log
        log_data = CreateAuditLogRequest(
            user_id=user.id,
            event_type="DELETE_PROJECT_FAILURE",
            reason="Project has been deleted already",
        )
        create_audit_log(db=db, request=request, log_data=log_data)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project has been deleted already",
        )

    project.is_deleted = True  # type: ignore
    db.commit()
    db.refresh(project)

    # Logging
    logger.info(
        "Project deleted successfully",
        extra={"user_id": user.id, "project_id": project.id},
    )

    # Audit log
    log_data = CreateAuditLogRequest(
        user_id=user.id,
        event_type="DELETE_PROJECT_SUCCESS",
    )
    create_audit_log(db=db, request=request, log_data=log_data)

    return {"message": "Project has been successfully deleted"}
