import logging
import logging.config
import sys
# from uvicorn.logging import DefaultFormatter

LOG_FILE_PATH = ".log"

LOGGING_CONFIG: dict = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        # 檔案用的標準 formatter
        "standard": {
            "format": "%(asctime)s,%(msecs)03d [%(levelname)s] %(filename)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        # console 用的彩色 formatter
        "colored": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s%(filename)s:%(lineno)d [%(asctime)s] %(message)s",
            "datefmt": "%H:%M:%S",
            "use_colors": True,
        },
    },

    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "level": "INFO",
            "formatter": "standard",    # 指向 formatters.standard
            "filename": LOG_FILE_PATH,
            "mode": "a",
        },
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "colored",     # 指向 formatters.colored
            "stream": "ext://sys.stdout",
        },
    },

    "loggers": {
        "": {  # root logger
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

logging.config.dictConfig(LOGGING_CONFIG)

logger = logging.getLogger(__name__)

logging.debug("這是 DEBUG")
logging.info("這是 INFO")
logging.warning("這是 WARNING")
logging.error("這是 ERROR")
