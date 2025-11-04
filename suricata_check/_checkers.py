"""The `suricata_check.suricata_check` module contains the command line utility and the main program logic."""

import logging
import logging.handlers
import pkgutil
from collections.abc import Sequence
from functools import lru_cache

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.checkers.interface.dummy import DummyChecker
from suricata_check.utils.checker_typing import (
    get_all_subclasses,
)
from suricata_check.utils.regex import get_regex_provider

_regex_provider = get_regex_provider()

_logger = logging.getLogger(__name__)

# Global variable to check if extensions have already been imported in case get_checkers() is called multiple times.
suricata_check_extensions_imported = False


def _import_extensions() -> None:
    global suricata_check_extensions_imported  # noqa: PLW0603
    if suricata_check_extensions_imported is True:
        return

    for module in pkgutil.iter_modules():
        if module.name.startswith("suricata_check_"):
            try:
                imported_module = __import__(module.name)
                _logger.info(
                    "Detected and successfully imported suricata-check extension %s with version %s.",
                    module.name.replace("_", "-"),
                    getattr(imported_module, "__version__"),
                )
            except ImportError:
                _logger.warning(
                    "Detected potential suricata-check extension %s but failed to import it.",
                    module.name.replace("_", "-"),
                )
    suricata_check_extensions_imported = True


@lru_cache(maxsize=1)
def get_checkers(
    include: Sequence[str] = (".*",),
    exclude: Sequence[str] = (),
    issue_severity: int = logging.INFO,
) -> Sequence[CheckerInterface]:
    """Auto discovers all available checkers that implement the CheckerInterface.

    Returns:
    A list of available checkers that implement the CheckerInterface.

    """
    # Check for extensions and try to import them
    _import_extensions()

    checkers: list[CheckerInterface] = []
    for checker in get_all_subclasses(CheckerInterface):
        if checker.__name__ == DummyChecker.__name__:
            continue

        # Initialize DummyCheckers to retrieve error messages.
        if issubclass(checker, DummyChecker):
            checker()

        enabled, relevant_codes = __get_checker_enabled(
            checker, include, exclude, issue_severity
        )

        if enabled:
            checkers.append(checker(include=relevant_codes))

        else:
            _logger.info("Checker %s is disabled.", checker.__name__)

    _logger.info(
        "Discovered and enabled checkers: [%s]",
        ", ".join([c.__class__.__name__ for c in checkers]),
    )
    if len(checkers) == 0:
        _logger.warning(
            "No checkers were enabled. Check the include and exclude arguments."
        )

    # Perform a uniqueness check on the codes emmitted by the checkers
    for checker1 in checkers:
        for checker2 in checkers:
            if checker1 == checker2:
                continue
            if not set(checker1.codes).isdisjoint(checker2.codes):
                msg = f"Checker {checker1.__class__.__name__} and {checker2.__class__.__name__} have overlapping codes."
                _logger.error(msg)

    return sorted(checkers, key=lambda x: x.__class__.__name__)


def __get_checker_enabled(
    checker: type[CheckerInterface],
    include: Sequence[str],
    exclude: Sequence[str],
    issue_severity: int,
) -> tuple[bool, set[str]]:
    enabled = checker.enabled_by_default

    # If no include regexes are provided, include all by default
    if len(include) == 0:
        relevant_codes = set(checker.codes.keys())
    else:
        # If include regexes are provided, include all codes that match any of these regexes
        relevant_codes = set()

        for regex in include:
            relevant_codes.update(
                set(
                    filter(
                        lambda code: _regex_provider.compile("^" + regex + "$").match(
                            code
                        )
                        is not None,
                        checker.codes.keys(),
                    )
                )
            )

        if len(relevant_codes) > 0:
            enabled = True

    # Now remove the codes that are excluded according to any of the provided exclude regexes
    for regex in exclude:
        relevant_codes = set(
            filter(
                lambda code: _regex_provider.compile("^" + regex + "$").match(code)
                is None,
                relevant_codes,
            )
        )

    # Now filter out irrelevant codes based on severity
    relevant_codes = set(
        filter(
            lambda code: checker.codes[code]["severity"] >= issue_severity,
            relevant_codes,
        )
    )

    if len(relevant_codes) == 0:
        enabled = False

    return enabled, relevant_codes
