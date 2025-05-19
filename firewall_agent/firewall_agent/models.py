"""ORM definitions – mirror local state for reverse‑proxies / aliases / rules."""
from sqlalchemy import Column, Integer, String, DateTime, func
from .database import Base, engine


class ReverseProxyDB(Base):
    __tablename__ = "reverse_proxies"

    id = Column(String(36), primary_key=True, index=True)  # UUID
    name = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    ports = Column(String, nullable=False)        # e.g. "80,443"
    allowed_ips = Column(String, nullable=False)  # comma‑separated CIDRs


class AliasDB(Base):
    __tablename__ = "aliases"

    id = Column(String(36), primary_key=True, index=True)  # OPNsense UUID
    service_name = Column(String, nullable=False)


class RuleDB(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    firewall_rule_uuid = Column(String, nullable=False, unique=True)
    action = Column(String, nullable=False)
    src_ip = Column(String, nullable=False)
    dest_alias_id = Column(String(36), nullable=False)


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


# Create tables on first import – SQLite is file‑based so safe for dev
Base.metadata.create_all(bind=engine)
