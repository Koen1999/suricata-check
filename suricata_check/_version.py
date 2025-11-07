import datetime
import json
import logging
import os
import re
import subprocess
from functools import lru_cache
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

__user_agent = f"suricata-check/{__version__} (+https://suricata-check.teuwen.net/)"


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
    cached_data = __get_saved_check_update()
    headers = {"User-Agent": __user_agent}
    if cached_data is not None:
        if (
            "response_headers" in cached_data
            and "etag" in cached_data["response_headers"]
        ):
            headers["If-None-Match"] = cached_data["response_headers"]["etag"]
        if "last_checked" in cached_data:
            headers["If-Modified-Since"] = datetime.datetime.fromisoformat(
                cached_data["last_checked"]
            ).strftime("%a, %d %b %Y %H:%M:%S GMT")

    try:
        response = requests.get(
            "https://pypi.org/pypi/suricata-check/json", headers=headers, timeout=5
        )

        if response.status_code == requests.codes.ok:
            pypi_json = response.json()
            __save_check_update(
                pypi_json, {k.lower(): v for k, v in response.headers.items()}
            )
            return pypi_json["info"]["version"]

        if response.status_code == requests.codes.not_modified:
            assert cached_data is not None
            _logger.debug("Using cached PyPI response data for update check.")
            return cached_data["pypi_json"]["info"]["version"]
    except requests.RequestException:
        _logger.warning("Failed to perform update check.")
    return None


@lru_cache(maxsize=1)
def __get_saved_check_update() -> Optional[dict]:
    if not os.path.exists(UPDATE_CHECK_CACHE_PATH):
        return None

    try:
        with open(UPDATE_CHECK_CACHE_PATH, "r") as f:
            data = json.load(f)
    except OSError:
        _logger.warning("Failed to read last date version was checked from cache file.")
        os.remove(UPDATE_CHECK_CACHE_PATH)
        return None
    except json.JSONDecodeError:
        _logger.warning(
            "Failed to decode cache file to determine last date version was checked."
        )
        return None

    if not isinstance(data, dict):
        _logger.warning(
            "Cache file documenting the last date version was checked is malformed."
        )
        os.remove(UPDATE_CHECK_CACHE_PATH)
        return None

    return data


def __should_check_update() -> bool:
    current_version = __version__
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

    data = __get_saved_check_update()
    if data is None:
        return True

    try:
        last_checked = datetime.datetime.fromisoformat(data["last_checked"])
        if (datetime.datetime.now(tz=datetime.timezone.utc) - last_checked).days < 1:
            return False
    except KeyError:
        _logger.warning(
            "Cache file documenting the last date version was checked is malformed."
        )

    return True


def __save_check_update(pypi_json: dict, response_headers: dict) -> None:
    try:
        with open(UPDATE_CHECK_CACHE_PATH, "w") as f:
            json.dump(
                {
                    "last_checked": datetime.datetime.now(
                        tz=datetime.timezone.utc
                    ).isoformat(),
                    "pypi_json": pypi_json,
                    "response_headers": response_headers,
                },
                f,
            )
    except OSError:
        _logger.warning("Failed to write current date to cache file for update checks.")


def check_for_update() -> None:
    if not __should_check_update():
        return

    current_version = __version__
    latest_version = __get_latest_version()

    if latest_version is None:
        _logger.warning("Failed to check for updates of suricata-check.")
        return

    if Version(latest_version) > Version(current_version):
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
        return

    _logger.info(
        "You are using the latest version of suricata-check (%s).", __version__
    )
