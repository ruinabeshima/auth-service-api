from fastapi import FastAPI
from src.api.v1 import auth_routes, admin_routes, project_routes, health_routes

app = FastAPI()

app.include_router(auth_routes.router, tags=["Auth"])
app.include_router(admin_routes.router, tags=["Admin"])
app.include_router(project_routes.router, tags=["Projects"])
app.include_router(health_routes.router, tags=["Health"])
