import logging
import os
import subprocess
from importlib.metadata import PackageNotFoundError, version


def _get_git_revision_short_hash() -> str:
    return (
        subprocess.check_output(["git", "rev-parse", "--short", "HEAD"])
        .decode("ascii")
        .strip()
    )


logger = logging.getLogger(__name__)

__version__: str = "unknown"


git_dir = os.path.join(os.path.dirname(__file__), "..", ".git")
if os.path.exists(git_dir):
    __version__ = _get_git_revision_short_hash()
    logger.debug("Detected suricata-check version using git: %s", __version__)
else:
    try:
        __version__ = version("suricata-check")
        logger.debug("Detected suricata-check version using importlib: %s", __version__)
    except PackageNotFoundError:
        logger.debug("Failed to detect suricata-check version: %s", __version__)
