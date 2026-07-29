"""
Structured logging module for AutoDeploy CLI.
Provides colorized console output and optional structured log output.
"""

import sys
import logging
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler

console = Console()

def setup_logger(name: str = "autodeploy", level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configures and returns a logger instance with Rich formatting."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Rich console handler for beautiful CLI output
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True
    )
    rich_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    formatter = logging.Formatter("%(message)s")
    rich_handler.setFormatter(formatter)
    logger.addHandler(rich_handler)

    # Optional file logger
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger

logger = setup_logger()
