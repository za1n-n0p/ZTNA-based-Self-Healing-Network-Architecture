"""
logger_utils.py — Shared Logging Utility
==========================================
ZTNA Self-Healing Network | NIST SP 800-207
Used by: pdp_agent.py, pep_agent.py, ids_agent.py

Creates both file and console handlers so every agent keeps a dated log file
alongside its console output.  Import once at the top of each agent module.
"""

import logging
import sys
from datetime import datetime


def setup_agent_logger(agent_name: str, log_level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return a Logger for the given agent.

    Args:
        agent_name : Short label used in log output and filename  ("PDP", "PEP", "IDS").
        log_level  : logging.INFO by default; pass logging.DEBUG for verbose output.

    Returns:
        Configured Logger instance.

    Log file: <agent_name_lower>_YYYYMMDD.log  (rotated daily by filename only —
              for production use logging.handlers.TimedRotatingFileHandler instead).
    """
    logger = logging.getLogger(agent_name)
    logger.setLevel(log_level)

    # Prevent duplicate handlers if called more than once (e.g. in tests)
    logger.handlers.clear()
    logger.propagate = False

    # ── File handler ──────────────────────────────────────────────────────
    log_filename = f"{agent_name.lower()}_{datetime.now().strftime('%Y%m%d')}.log"
    try:
        file_handler = logging.FileHandler(log_filename, encoding="utf-8")
        file_handler.setLevel(log_level)
    except OSError as exc:
        # Fall back gracefully if the log file cannot be created (e.g. read-only FS)
        print(f"[LOGGER] WARNING — could not create log file {log_filename!r}: {exc}", file=sys.stderr)
        file_handler = None

    # ── Console handler ───────────────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # ── Formatter ─────────────────────────────────────────────────────────
    fmt = logging.Formatter(
        "%(asctime)s | %(name)-4s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(fmt)
    if file_handler:
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    logger.addHandler(console_handler)

    logger.info("Logger initialised — output: console + %s", log_filename)
    return logger
