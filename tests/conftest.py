import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.database import Base, get_db
from src.main import app
from fastapi.testclient import TestClient
from dotenv import load_dotenv
import os

load_dotenv()

TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL", "postgresql://admin:Ruissa0223@localhost:5433/tests_db"
)
engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# Fixture which wipes the database before every test
@pytest.fixture(scope="function", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)
