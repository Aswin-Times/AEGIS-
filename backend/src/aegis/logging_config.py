import json
import logging
from datetime import UTC, datetime

_FIELDS = ("request_id", "method", "path", "status", "duration_ms", "tenant_id", "tool")


class JsonFormatter(logging.Formatter):
    """Structured logs. Only named fields are emitted, so bodies and headers stay out."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _FIELDS:
            if hasattr(record, field):
                entry[field] = getattr(record, field)
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("aegis")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
