"""The `suricata_check.checkers.interface.checker` module contains the `CheckerInterface`.

Implementation of the `CheckerInterface` is neccessary for checker auto-discovery.
"""

import abc
import logging
from collections.abc import Iterable, Mapping
from typing import Optional

import idstools.rule

from suricata_check.utils.checker import get_rule_option, is_rule_option_set
from suricata_check.utils.checker_typing import ISSUES_TYPE

_logger = logging.getLogger(__name__)


class CheckerInterface:
    """Interface for rule checkers returning a list of issues.

    These checkers are automatically discovered through `suricata_check.suricata_check.get_checkers()`.

    Each code should start with an upper case letter (may be multiple), followed by three digits.
    In other words, each code should follow the following regex `[A-Z]{1,}[0-9]{3}`

    We recommend using a letter to indicate the category of the issue, such as described in `README.md`.
    Moreover, we suggest to reserve certain ranges of numbers for each checker.

    """

    codes: Mapping[str, Mapping[str, int]]
    """A Mapping of issue codes emitted by the checker to metadata for those issue types.
    The metadata is structured in the form of a Mapping from attribute name to attribute value.
    The one mandatory metadata attribute is severity, which must be one of the levels provided by the `logging` module"""

    enabled_by_default: bool = True
    """A boolean indicating if the checker is enabled by default when discovered automatically."""

    def __init__(
        self: "CheckerInterface", include: Optional[Iterable[str]] = None
    ) -> None:
        """Initializes the checker given a list of issue codes to emit."""
        if include is None:
            include = self.codes
        self.include = include

        super().__init__()

    def check_rule(
        self: "CheckerInterface",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        """Checks a rule and returns a list of issues found."""
        self.__log_rule_processing(rule)
        return self.__add_checker_metadata(
            self.__add_issue_metadata(self.__filter_issues(self._check_rule(rule)))
        )

    @abc.abstractmethod
    def _check_rule(
        self: "CheckerInterface",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        """Checks a rule and returns a list of issues found."""

    def __log_rule_processing(
        self: "CheckerInterface",
        rule: idstools.rule.Rule,
    ) -> None:
        sid: Optional[int] = None
        if is_rule_option_set(rule, "sid"):
            sid_str = get_rule_option(rule, "sid")
            assert sid_str is not None
            sid = int(sid_str)

        _logger.debug("Running %s on rule %s", self.__class__.__name__, sid)

    def __add_issue_metadata(
        self: "CheckerInterface",
        issues: ISSUES_TYPE,
    ) -> ISSUES_TYPE:
        """Given a list of issues, return the same list with metadata from the issue types."""
        for issue in issues:
            metadata = self.codes[issue.code]
            if "severity" in metadata:
                issue.severity = metadata["severity"]

        return issues

    def __add_checker_metadata(
        self: "CheckerInterface",
        issues: ISSUES_TYPE,
    ) -> ISSUES_TYPE:
        """Given a list of issues, return the same list with metadata from the checker."""
        name = self.__class__.__name__

        for issue in issues:
            issue.checker = name

        return issues

    def __filter_issues(
        self: "CheckerInterface",
        issues: ISSUES_TYPE,
    ) -> ISSUES_TYPE:
        """Given a list of issues, return the same list having filtered out disabled issue types."""
        filtered_issues = []

        for issue in issues:
            if issue.code in self.include:
                filtered_issues.append(issue)
            elif issue.code not in self.codes:
                _logger.warning(
                    "Issue with filtered code %s not found in checker %s",
                    issue.code,
                    self.__class__.__name__,
                )

        return filtered_issues
