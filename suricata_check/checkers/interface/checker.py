"""The `suricata_check.checkers.interface.checker` module contains the `CheckerInterface`.

Implementation of the `CheckerInterface` is neccessary for checker auto-discovery.
"""

import abc
import logging
from collections.abc import Iterable
from typing import Optional

import idstools.rule

from suricata_check.utils.checker import get_rule_option, is_rule_option_set
from suricata_check.utils.typing import ISSUES_TYPE

logger = logging.getLogger(__name__)


class CheckerInterface:
    """Interface for rule checkers returning a list of issues.

    These checkers are automatically discovered through `suricata_check.suricata_check.get_checkers()`.

    Each code should start with an upper case letter (may be multiple), followed by three digits.
    In other words, each code should follow the following regex `[A-Z]{1,}[0-9]{3}`

    We recommend using a letter to indicate the category of the issue, such as described in `README.md`.
    Moreover, we suggest to reserve certain ranges of numbers for each checker.

    Attributes
    ----------
        codes: A list of issue codes emitted by the checker.

    """

    codes: Iterable[str]

    def check_rule(
        self: "CheckerInterface",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        """Checks a rule and returns a list of issues found.

        Args:
        ----
        rule (idstool.rule.Rule): The rule to be checked.

        Returns:
        -------
        ISSUES_TYPE: A sequence of issues found in the rule.

        """
        self._log_rule_processing(rule)
        return self._add_checker_metadata(self._check_rule(rule))

    @abc.abstractmethod
    def _check_rule(
        self: "CheckerInterface",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        """Checks a rule and returns a list of issues found.

        Args:
        ----
        rule (idstool.rule.Rule): The rule to be checked.

        Returns:
        -------
        ISSUES_TYPE: A sequence of issues found in the rule.

        """

    def _log_rule_processing(
        self: "CheckerInterface",
        rule: idstools.rule.Rule,
    ) -> None:
        sid: Optional[int] = None
        if is_rule_option_set(rule, "sid"):
            sid_str = get_rule_option(rule, "sid")
            assert sid_str is not None
            sid = int(sid_str)

        logger.debug("Running %s on rule %i", self.__class__.__name__, sid)

    def _add_checker_metadata(
        self: "CheckerInterface",
        issues: ISSUES_TYPE,
    ) -> ISSUES_TYPE:
        """Given a list of issues, return the same list with metadata from the checker."""
        name = self.__class__.__name__

        for issue in issues:
            issue.checker = name

        return issues
