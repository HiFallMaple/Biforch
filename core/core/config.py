import logging
import logging.config
import sys
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr, ValidationError, field_validator
from pathlib import Path


class Settings(BaseSettings):
    DB_PATH: Path = Field(
        "./data/core.db", description="SQLite database file path")
    TIMEOUT: int = Field(10, gt=0, description="HTTP request timeout seconds")
    ADMIN_TOKEN: SecretStr = Field(..., description="Admin bearer token")
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
            "level": "DEBUG",
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
