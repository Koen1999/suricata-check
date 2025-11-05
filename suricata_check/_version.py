import datetime
import json
import logging
import os
import re
import subprocess
from importlib.metadata import PackageNotFoundError, requires, version
from typing import Optional

import requests
from packaging.version import Version

SURICATA_CHECK_DIR = os.path.dirname(__file__)
UPDATE_CHECK_CACHE_PATH = os.path.expanduser("~/.suricata_check_version_check.json")

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
            import setuptools_git_versioning  # noqa: RUF100, PLC0415

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


def __get_latest_version() -> Optional[str]:
    try:
        response = requests.get("https://pypi.org/pypi/suricata-check/json", timeout=2)
        if response.status_code == 200:  # noqa: PLR2004
            return response.json()["info"]["version"]
    except requests.RequestException:
        pass
    return None


def __should_check_update() -> bool:
    current_version = get_version()
    if current_version == "unknown":
        _logger.warning(
            "Skipping update check because current version cannot be determined."
        )
        return False
    if "dirty" in current_version:
        _logger.warning("Skipping update check because local changes are detected.")
        return False

    if not os.path.exists(UPDATE_CHECK_CACHE_PATH):
        return True

    try:
        with open(UPDATE_CHECK_CACHE_PATH, "r") as f:
            data = json.load(f)
            last_checked = datetime.datetime.fromisoformat(data["last_checked"])
            if (
                datetime.datetime.now(tz=datetime.timezone.utc) - last_checked
            ).days < 1:
                return False
    except OSError:
        _logger.warning("Failed to read last date version was checked from cache file.")
    except json.JSONDecodeError:
        _logger.warning(
            "Failed to decode cache file to determine last date version was checked."
        )
    except KeyError:
        _logger.warning(
            "Cache file documenting the last date version was checked is malformed."
        )

    return True


def __save_check_time() -> None:
    try:
        with open(UPDATE_CHECK_CACHE_PATH, "w") as f:
            json.dump(
                {
                    "last_checked": datetime.datetime.now(
                        tz=datetime.timezone.utc
                    ).isoformat()
                },
                f,
            )
    except OSError:
        _logger.warning("Failed to write current date to cache file for update checks.")


def check_for_update() -> None:
    if not __should_check_update():
        return

    current_version = get_version()
    latest_version = __get_latest_version()

    if latest_version and Version(latest_version) > Version(current_version):
        _logger.warning(
            "A new version of suricata-check is available: %s (you have %s)",
            latest_version,
            current_version,
        )
        _logger.warning("Run `pip install --upgrade suricata-check` to update.")
        _logger.warning(
            "You can find the full changelog of what has changed here: %s",
            "https://github.com/Koen1999/suricata-check/releases",
        )

    __save_check_time()
