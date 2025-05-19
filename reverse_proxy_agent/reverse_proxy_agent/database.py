"""Database bootstrap (engine / session / Base)."""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

DATABASE_URL = f"sqlite:///{settings.DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Session factory
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# Declarative base class
Base = declarative_base()
