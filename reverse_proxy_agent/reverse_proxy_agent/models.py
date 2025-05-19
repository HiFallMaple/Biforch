"""SQLAlchemy ORM models."""
from sqlalchemy import Column, Integer, String, DateTime, func
from .database import Base, engine

class RuleDB(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False)
    ip = Column(String, nullable=False)

class ServiceDB(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    core_service_id = Column(Integer, nullable=False, unique=True)

class AgentCredentials(Base):
    __tablename__ = "agent_credentials"

    uuid = Column(String(36), primary_key=True, index=True)
    token = Column(String, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# Auto-create tables
Base.metadata.create_all(bind=engine)
