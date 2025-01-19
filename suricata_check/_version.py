import logging
import os
import re
import subprocess
from importlib.metadata import PackageNotFoundError, requires, version

SURICATA_CHECK_DIR = os.path.dirname(__file__)

_logger = logging.getLogger(__name__)


def __get_git_revision_short_hash() -> str:
    return (
        subprocess.check_output(["git", "rev-parse", "--short", "HEAD"])
        .decode("ascii")
        .strip()
    )


def get_version() -> str:
    v = "unknown"

    git_dir = os.path.join(SURICATA_CHECK_DIR, "..", ".git")
    if os.path.exists(git_dir):
        try:
            import setuptools_git_versioning

            v = str(
                setuptools_git_versioning.get_version(
                    root=os.path.join(SURICATA_CHECK_DIR, "..")
                )
            )
            _logger.debug(
                "Detected suricata-check version using setuptools_git_versioning: %s", v
            )
        except:  # noqa: E722
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


def get_dependency_versions() -> dict:
    d = {}

    requirements = None
    try:
        requirements = requires("suricata-check")
        _logger.debug("Detected suricata-check requirements using importlib")
    except PackageNotFoundError:
        requirements_path = os.path.join(SURICATA_CHECK_DIR, "..", "requirements.txt")
        if os.path.exists(requirements_path):
            with open(requirements_path) as fh:
                requirements = fh.readlines()
                requirements = filter(
                    lambda x: len(x.strip()) == 0 or x.strip().startswith("#"),
                    requirements,
                )

            _logger.debug("Detected suricata-check requirements using requirements.txt")
    finally:
        if requirements is None:
            _logger.debug("Failed to detect suricata-check requirements")
            return d

    for requirement in requirements:
        match = re.compile(r"""^([^=<>]+)(.*)$""").match(requirement)
        if match is None:
            _logger.debug("Failed to parse requirement: %s", requirement)
            continue
        required_package, _ = match.groups()
        try:
            d[required_package] = version(required_package)
        except PackageNotFoundError:
            d[required_package] = "unknown"

    return d
