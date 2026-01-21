"""Logging helpers for the static traffic analyzer."""
from __future__ import annotations

from dataclasses import dataclass
import logging
from logging.handlers import QueueHandler, QueueListener
from multiprocessing import Queue


_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.CRITICAL,
    "critical": logging.CRITICAL,
}


@dataclass(frozen=True)
class LoggingContext:
    """Container for logging configuration shared across processes."""

    queue: Queue | None
    listener: QueueListener | None


def _resolve_level(level: str) -> int:
    """Return a logging level integer from a string."""
    normalized = (level or "info").strip().lower()
    if normalized not in _LEVEL_MAP:
        raise ValueError(f"Unsupported log level: {level}")
    return _LEVEL_MAP[normalized]


def _build_handlers(log_file: str | None) -> list[logging.Handler]:
    """Create the base handlers used for log output."""
    handler: logging.Handler
    if log_file:
        handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s %(processName)s %(levelname)s %(name)s - %(message)s"
    )
    handler.setFormatter(formatter)
    return [handler]


def configure_logging(
    level: str,
    log_file: str | None = None,
    use_queue: bool = False,
) -> LoggingContext:
    """Configure logging for the current process and optionally enable multiprocessing."""
    numeric_level = _resolve_level(level)
    handlers = _build_handlers(log_file)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(numeric_level)
    if not use_queue:
        for handler in handlers:
            root_logger.addHandler(handler)
        return LoggingContext(queue=None, listener=None)

    queue: Queue = Queue()
    queue_handler = QueueHandler(queue)
    root_logger.addHandler(queue_handler)
    listener = QueueListener(queue, *handlers, respect_handler_level=True)
    listener.start()
    return LoggingContext(queue=queue, listener=listener)


def configure_worker_logging(queue: Queue | None, level: str) -> None:
    """Configure logging for worker processes to forward logs to the parent."""
    numeric_level = _resolve_level(level)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(numeric_level)
    if queue is None:
        root_logger.addHandler(logging.NullHandler())
        return
    root_logger.addHandler(QueueHandler(queue))


def stop_listener(context: LoggingContext) -> None:
    """Stop the queue listener if one was started."""
    if context.listener:
        context.listener.stop()
