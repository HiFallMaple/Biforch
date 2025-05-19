# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from reverse_proxy_agent.database import Base
from reverse_proxy_agent.api import app
from reverse_proxy_agent.dependencies import get_db as original_get_db

@pytest.fixture(scope="session")
def test_engine(tmp_path_factory):
    """Create a new SQLite engine for testing."""
    db_file = tmp_path_factory.mktemp("data") / "test.db"
    engine = create_engine(
        f"sqlite:///{db_file}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    return engine

@pytest.fixture(autouse=True)
def clean_db(test_engine):
    """Drop and recreate all tables before each test to avoid unique-constraint conflicts."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

@pytest.fixture()
def db_session(test_engine):
    """Provide a SQLAlchemy session bound to the test engine."""
    SessionLocal = sessionmaker(
        bind=test_engine, autocommit=False, autoflush=False
    )
    session = SessionLocal()
    yield session
    session.close()

@pytest.fixture()
def client(db_session):
    """Create a TestClient that uses the db_session via dependency override."""
    def _override_get_db():
        yield db_session
    app.dependency_overrides[original_get_db] = _override_get_db
    return TestClient(app)
