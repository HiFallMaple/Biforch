from __future__ import annotations

import ipaddress
import logging
import logging.config
import sys
from pathlib import Path
from typing import Dict

from pydantic import AnyHttpUrl, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings for Biforch Firewall Agent.

    - Loads settings from environment variables via pydantic-settings
    - Validates values on startup (fails fast)
    """
    # External service URLs
    CORE_URL: AnyHttpUrl = Field(..., description="URL of Biforch Core service")
    REMOTE_URL: AnyHttpUrl = Field(..., description="Base URL of OPNsense firewall")
    AGENT_URL: AnyHttpUrl = Field(..., description="Callback/API URL of this agent")

    # Firewall authentication
    API_KEY: str = Field(..., description="OPNsense API key")
    API_SECRET: str = Field(..., description="OPNsense API secret")

    # Alias configuration
    PREFIX: str = Field(
        "Biforch_",
        min_length=1,
        description="Prefix for OPNsense aliases"
    )
    AGENT_NAME: str = Field(..., description="Logical name of this agent")
    CALLBACK_PATH: str = Field(
        "/registrations",
        description="Core callback endpoint path"
    )

    # Runtime behavior
    TIMEOUT: int = Field(
        10,
        description="Outbound HTTP timeout in seconds",
        gt=0
    )
    DB_PATH: Path = Field(
        "./data/db.sqlite",
        description="Path to SQLite database file"
    )

    # Server settings
    INTERNAL_HOST: str = Field(
        "0.0.0.0",
        description="Uvicorn server host"
    )
    INTERNAL_PORT: int = Field(
        8000,
        description="Uvicorn server port",
        ge=1,
        le=65535
    )
    RELOAD: bool = Field(
        False,
        description="Enable Uvicorn auto-reload in development"
    )

    # Internal mappings
    ACTION_MAP: Dict[str, str] = Field(
        default_factory=lambda: {"pass": "pass", "block": "block", "reject": "block"},
        description="Map OPNsense actions to Core contract"
    )

    # Logging
    LOG_FILE_PATH: Path = Field(
        "./data/.log",
        description="Path to log file"
    )

    # Pydantic settings
    model_config = {
        "extra": "ignore",
        "case_sensitive": True,
        "env_file": ".env",
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

    @field_validator("LOG_FILE_PATH", mode="before")
    @classmethod
    def _validate_log_file_path(cls, v: str | Path) -> Path:
        path = Path(v)
        parent = path.parent
        if not parent.exists():
            raise ValueError(f"LOG_FILE_PATH directory does not exist: {parent}")
        return path

    @field_validator("INTERNAL_HOST", mode="before")
    @classmethod
    def _validate_internal_host(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"INTERNAL_HOST must be a valid IP address: {v}")
        return v

    @field_validator("PREFIX", mode="before")
    @classmethod
    def _validate_prefix(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("PREFIX cannot be empty")
        return v

    @field_validator("CALLBACK_PATH", mode="before")
    @classmethod
    def _validate_callback_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("CALLBACK_PATH must start with '/'")
        return v

    @field_validator("ACTION_MAP", mode="before")
    @classmethod
    def _validate_action_map(cls, v: Dict[str, str]) -> Dict[str, str]:
        if not isinstance(v, dict) or not v:
            raise ValueError("ACTION_MAP must be a non-empty dict")
        return v

    @field_validator("RELOAD", mode="before")
    @classmethod
    def _parse_reload_flag(cls, v: bool | str) -> bool:
        if isinstance(v, str):
            val = v.lower()
            if val in ("true", "1", "yes"):
                return True
            if val in ("false", "0", "no"):
                return False
            raise ValueError("RELOAD must be a boolean value")
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
