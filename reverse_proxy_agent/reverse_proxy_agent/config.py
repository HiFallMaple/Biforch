# reverse_proxy_agent/config.py
"""
Centralised runtime configuration for Reverse Proxy Agent.

- Loads settings from environment variables via pydantic-settings
- Validates values on import (fails fast)
- Defines database paths, service URLs, and server behaviour
"""
from __future__ import annotations

import logging
import logging.config
import sys
from pathlib import Path
from typing import Literal, List

from pydantic import AnyHttpUrl, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment.

    Attributes:
        DB_PATH: Path to SQLite database file for reverse proxy state
        CONFIG_DIR: Directory where proxy configuration snippets are written
        CORE_URL: URL of Biforch Core service
        AGENT_URL: Callback/API URL of this agent
        REVERSE_PROXY_IP: IP address used by the reverse proxy
        REVERSE_PROXY_PORTS: List of ports exposed by the reverse proxy

        AGENT_NAME: Logical name of this agent
        CALLBACK_PATH: Endpoint path for Core callbacks

        PROXY_BACKEND: Proxy engine type (nginx, caddy, traefik, haproxy)
        TIMEOUT: HTTP request timeout (seconds)

        INTERNAL_HOST: Uvicorn bind host
        INTERNAL_PORT: Uvicorn bind port
        RELOAD: Enable Uvicorn auto-reload in development
    """
    # default put db in data dir
    DB_PATH: Path = Field(
        "./data/db.sqlite",
        description="Path to SQLite database file",
    )
    CONFIG_DIR: Path = Field(...,
                             description="Directory for proxy config snippets")

    # External service URLs
    CORE_URL: AnyHttpUrl = Field(..., description="Biforch Core service URL")
    AGENT_URL: AnyHttpUrl = Field(...,
                                  description="This agent's callback/API URL")

    # Reverse proxy network settings
    REVERSE_PROXY_IP: str = Field(...,
                                  description="IP address for reverse proxy to bind")
    REVERSE_PROXY_PORTS: List[int] = Field(
        default_factory=list,
        description="Ports exposed by reverse proxy, as a list or comma-separated string"
    )

    # Identification
    AGENT_NAME: str = Field(...,
                            description="Logical name of the reverse proxy agent")
    CALLBACK_PATH: str = Field(
        "/registrations", description="Endpoint path for Core callback"
    )

    # Proxy backend selection
    PROXY_BACKEND: Literal["nginx", "caddy", "traefik", "haproxy"] = Field(
        ..., description="Proxy engine type"
    )

    # Runtime behavior
    TIMEOUT: int = Field(..., description="HTTP request timeout in seconds")

    # Server settings
    INTERNAL_HOST: str = Field(
        "0.0.0.0", description="Uvicorn bind host"
    )
    INTERNAL_PORT: int = Field(
        8000, description="Uvicorn bind port"
    )
    RELOAD: bool = Field(
        False, description="Enable Uvicorn auto-reload in development"
    )

    # Logging
    LOG_FILE_PATH: Path = Field("./data/.log", description="Path to log file")

    # Pydantic model configuration
    model_config = {
        "extra": "ignore",
        "env_file": ".env",
        "case_sensitive": True,
    }

    # ---------------------- Validators ----------------------
    @field_validator("DB_PATH", mode="before")
    @classmethod
    def _validate_db_path(cls, v: str | Path) -> Path:
        path = Path(v)
        parent = path.parent
        if not parent.exists():
            raise ValueError(f"DB_PATH directory does not exist: {parent}")
        return path

    @field_validator("CONFIG_DIR", mode="before")
    @classmethod
    def _validate_config_dir(cls, v: str | Path) -> Path:
        path = Path(v)
        if not path.exists():
            raise ValueError(f"CONFIG_DIR does not exist: {path}")
        if not path.is_dir():
            raise ValueError(f"CONFIG_DIR is not a directory: {path}")
        return path

    @field_validator("REVERSE_PROXY_IP", mode="before")
    @classmethod
    def _validate_reverse_proxy_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(
                f"REVERSE_PROXY_IP must be a valid IP address: {v}")
        return v

    @field_validator("REVERSE_PROXY_PORTS", mode="before")
    @classmethod
    def _validate_reverse_proxy_ports(cls, v: List[int] | str) -> List[int]:
        # Accept comma-separated string or list
        ports: List[int] = []
        if isinstance(v, str):
            parts = [p.strip() for p in v.split(",") if p.strip()]
            for p in parts:
                try:
                    num = int(p)
                except ValueError:
                    raise ValueError(f"Invalid port value: {p}")
                ports.append(num)
        else:
            ports = v
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port must be between 1 and 65535: {p}")
        return ports

    @field_validator("TIMEOUT", mode="before")
    @classmethod
    def _validate_timeout(cls, v: int | str) -> int:
        try:
            n = int(v)
        except Exception:
            raise ValueError("TIMEOUT must be an integer")
        if n <= 0:
            raise ValueError("TIMEOUT must be positive")
        return n

    @field_validator("INTERNAL_HOST", mode="before")
    @classmethod
    def _validate_host(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"INTERNAL_HOST must be a valid IP address: {v}")
        return v

    @field_validator("INTERNAL_PORT", mode="before")
    @classmethod
    def _validate_port(cls, v: int | str) -> int:
        try:
            port = int(v)
        except Exception:
            raise ValueError("INTERNAL_PORT must be an integer")
        if not (1 <= port <= 65535):
            raise ValueError("INTERNAL_PORT must be between 1 and 65535")
        return port

    @field_validator("RELOAD", mode="before")
    @classmethod
    def _validate_reload(cls, v: bool | str) -> bool:
        if isinstance(v, str):
            val = v.lower()
            if val in ("true", "1", "yes"):
                return True
            if val in ("false", "0", "no"):
                return False
            raise ValueError("RELOAD must be a boolean (true/false)")
        return bool(v)


LOGGING_CONFIG: dict = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "standard": {
            "format": "%(asctime)s,%(msecs)03d [%(levelname)s] %(filename)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "colored": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s [%(filename)s:%(lineno)d] [%(asctime)s] %(message)s",
            "datefmt": "%H:%M:%S",
            "use_colors": True,
        },
    },

    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "level": "INFO",
            "formatter": "standard",
            "filename": ".log",
            "mode": "a",
        },
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "colored",
            "stream": "ext://sys.stdout",
        },
    },

    "loggers": {
        "": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}


# Instantiate settings (fails on validation error)
try:
    settings = Settings()
    LOGGING_CONFIG["handlers"]["file"]["filename"] = settings.LOG_FILE_PATH
    logging.config.dictConfig(LOGGING_CONFIG)
    logging.info("Settings loaded successfully")
except ValidationError as exc:
    logging.error("🚨 Configuration error:\n", exc, file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    settings_json = settings.model_dump_json(indent=2)
    logging.info(f"{settings_json}")
