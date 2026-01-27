"""Logging configuration for OpsAgent."""

import logging
import logging.handlers
import json
import sys
from datetime import datetime
from typing import Dict


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add any extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename', 'funcName',
                          'levelname', 'levelno', 'lineno', 'module', 'msecs',
                          'message', 'pathname', 'process', 'processName',
                          'relativeCreated', 'thread', 'threadName', 'exc_info',
                          'exc_text', 'stack_info']:
                log_data[key] = value

        return json.dumps(log_data)


def setup_logger(config: Dict) -> logging.Logger:
    """
    Setup and configure the application logger.

    Args:
        config: Configuration dictionary containing logging settings

    Returns:
        Configured logger instance
    """
    logging_config = config.get('logging', {})

    # Get configuration
    log_level = logging_config.get('level', 'INFO').upper()
    log_format = logging_config.get('format', 'json')
    log_file = logging_config.get('file', '/var/log/ops-agent/ops-agent.log')
    max_size = logging_config.get('max_size_mb', 100) * 1024 * 1024
    backup_count = logging_config.get('backup_count', 5)
    console_output = logging_config.get('console_output', True)

    # Create logger
    logger = logging.getLogger('ops-agent')
    logger.setLevel(getattr(logging, log_level))
    logger.propagate = False

    # Remove existing handlers
    logger.handlers = []

    # Choose formatter
    if log_format == 'json':
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    # File handler with rotation
    try:
        import os
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not create file handler: {e}", file=sys.stderr)

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    logger.info(f"Logger initialized with level {log_level}")
    return logger
