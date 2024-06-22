import logging
import os
import subprocess
from importlib.metadata import PackageNotFoundError, version


def __get_git_revision_short_hash() -> str:
    return (
        subprocess.check_output(["git", "rev-parse", "--short", "HEAD"])
        .decode("ascii")
        .strip()
    )


_logger = logging.getLogger(__name__)


def get_version() -> str:
    v = "unknown"

    git_dir = os.path.join(os.path.dirname(__file__), "..", ".git")
    if os.path.exists(git_dir):
        v = __get_git_revision_short_hash()
        _logger.debug("Detected suricata-check version using git: %s", v)
    else:
        try:
            v = version("suricata-check")
            _logger.debug("Detected suricata-check version using importlib: %s", v)
        except PackageNotFoundError:
            _logger.debug("Failed to detect suricata-check version: %s", v)

    return v


__version__: str = get_version()
