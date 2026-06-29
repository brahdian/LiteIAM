from __future__ import annotations

"""Structlog configuration for production and development.

Call configure_logging() once at startup (before any loggers are obtained).

Production (ENVIRONMENT=production):
  - JSON output to stdout, one object per line
  - ISO 8601 UTC timestamps
  - Syslog-compatible log levels
  - Exception tracebacks serialized as dicts (ELK/Datadog friendly)
  - structlog.contextvars carries request_id, tenant_id across all log lines

Development:
  - Human-readable console renderer with colors
  - DEBUG level enabled
  - Same contextvars support (request_id shows up in local logs too)
"""

import logging
import sys

import structlog
from structlog.contextvars import merge_contextvars

from app.core.config import settings

_SERVICE_NAME = "auth-engine"


def configure_logging() -> None:
    """Configure structlog. Must be called before the first logger is obtained."""
    shared_processors: list = [
        # Merge bound context vars (request_id, tenant_id injected by middlewares)
        merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        # Add service metadata to every line for multi-service log aggregation
        structlog.processors.CallsiteParameterAdder(
            [structlog.processors.CallsiteParameter.FUNC_NAME]
        ),
    ]

    if settings.ENVIRONMENT == "production":
        processors = [
            *shared_processors,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]
        log_level = logging.INFO
        log_format = "%(message)s"
    else:
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(colors=True),
        ]
        log_level = logging.DEBUG
        log_format = "%(message)s"

    # Configure stdlib logging so libraries (uvicorn, sqlalchemy, httpx)
    # route through structlog's output channel.
    logging.basicConfig(
        format=log_format,
        stream=sys.stdout,
        level=log_level,
        force=True,
    )
    # Quiet noisy libraries in production
    if settings.ENVIRONMENT == "production":
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    # Use stdlib LoggerFactory so structlog wraps stdlib loggers — critical because
    # SQLAlchemy / asyncpg use logging.getLogger() and expect attributes like .name
    # that PrintLogger (structlog's own) does not provide.
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    structlog.get_logger(_SERVICE_NAME).info(
        "logging_configured",
        environment=settings.ENVIRONMENT,
        level="DEBUG" if log_level == logging.DEBUG else "INFO",
        format="json" if settings.ENVIRONMENT == "production" else "console",
    )
