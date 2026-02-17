from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, Request, Query
from src.database import get_db
from src.api.dependencies import get_current_user
from src.services import project_service
from src.schemas import CreateProject, ProjectResponse, PaginatedProjects, UpdateProject

router = APIRouter()


@router.get("/projects", response_model=PaginatedProjects)
def get_user_projects(
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    # Query parameters with validation
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
):
    return project_service.get_project(request, user, db, page, page_size)


@router.get("/projects/{id}", response_model=ProjectResponse)
def get_project_by_id(
    id: int,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return project_service.get_project_by_id(id, request, user, db)


@router.post("/projects/add", response_model=ProjectResponse)
def create_new_project(
    request: Request,
    project_data: CreateProject,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return project_service.add_project(request, project_data, user, db)


@router.patch("/projects/{id}", response_model=ProjectResponse)
def update_project(
    id: int,
    request: Request,
    project_update: UpdateProject,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return project_service.update_project(id, request, project_update, user, db)


@router.delete("/projects/{id}")
def delete_project(
    id: int,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return project_service.delete_project(id, request, user, db)
