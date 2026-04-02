"""
XLayer AI Logger - Logging configuration using Loguru
"""

import sys
from typing import Optional
from loguru import logger


def setup_logger(
    level: str = "INFO",
    log_file: Optional[str] = None,
    rotation: str = "10 MB",
    retention: str = "7 days"
) -> None:
    """
    Configure the logger for XLayer AI
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        rotation: Log rotation size
        retention: Log retention period
    """
    logger.remove()
    
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )
    
    logger.add(
        sys.stderr,
        format=log_format,
        level=level,
        colorize=True
    )
    
    if log_file:
        logger.add(
            log_file,
            format=log_format,
            level=level,
            rotation=rotation,
            retention=retention,
            compression="zip"
        )


def get_logger(name: str = "xlayer_ai"):
    """Get a logger instance with the given name"""
    return logger.bind(name=name)


scan_logger = get_logger("scan")
exploit_logger = get_logger("exploit")
report_logger = get_logger("report")
