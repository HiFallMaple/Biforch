import uuid
import secrets
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Enum as SAEnum,
    ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import relationship
from enum import Enum
from .database import Base

class PendingType(str, Enum):
    FIREWALL = "firewall"
    REVERSE_PROXY = "reverse_proxy"
    SERVICE_DISCOVERY = "service_discovery"

class FirewallDB(Base):
    __tablename__ = "firewalls"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, nullable=False)
    token = Column(String, nullable=False)
    name = Column(String, nullable=False, unique=True)
    api_url = Column(String, nullable=False)
    rules = relationship("RuleDB", back_populates="firewall", cascade="all, delete")

class ReverseProxyDB(Base):
    __tablename__ = "reverse_proxies"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, nullable=False)
    token = Column(String, nullable=False)
    name = Column(String, nullable=False, unique=True)
    ip = Column(String, nullable=False)
    ports = Column(String, nullable=False)
    api_url = Column(String, nullable=False)
    services = relationship(
        "ServiceDB", back_populates="reverse_proxy",
        cascade="all, delete",
        primaryjoin="ReverseProxyDB.uuid==ServiceDB.reverse_proxy_uuid",
    )

class ServiceDiscoveryDB(Base):
    __tablename__ = "service_discovery"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, nullable=False)
    token = Column(String, nullable=False)
    name = Column(String, nullable=False, unique=True)
    bind_reverse_proxy_id = Column(Integer, ForeignKey("reverse_proxies.id"), nullable=False)
    api_url = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reverse_proxy = relationship("ReverseProxyDB")

class ServiceDB(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    reverse_proxy_uuid = Column(String(36), ForeignKey("reverse_proxies.uuid"), nullable=False)
    reverse_proxy = relationship(
        "ReverseProxyDB", back_populates="services",
        primaryjoin="ServiceDB.reverse_proxy_uuid==ReverseProxyDB.uuid",
    )
    rules = relationship("RuleDB", back_populates="service", cascade="all, delete")

class RuleDB(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    firewall_rule_uuid = Column(String, nullable=False, unique=True)
    action = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    firewall_id = Column(Integer, ForeignKey("firewalls.id"), nullable=False)
    service = relationship("ServiceDB", back_populates="rules")
    firewall = relationship("FirewallDB", back_populates="rules")
    __table_args__ = (UniqueConstraint("ip", "service_id", name="uniq_ip_service"),)

class PendingRegistrationDB(Base):
    __tablename__ = "pending_registrations"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(SAEnum(PendingType), nullable=False)
    data = Column(String, nullable=False)
    src_ip = Column(String, nullable=False)
    secret = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)