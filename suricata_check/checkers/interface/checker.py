"""The `suricata_check.checkers.interface.checker` module contains the `CheckerInterface`.

Implementation of the `CheckerInterface` is neccessary for checker auto-discovery.
"""

import abc
from collections.abc import Iterable, Mapping, MutableMapping, Sequence

import idstools.rule


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

    @abc.abstractmethod
    def check_rule(
        self: "CheckerInterface",
        rule: idstools.rule.Rule,
    ) -> Sequence[Mapping]:
        """Checks a rule and returns a list of issues found.

        Args:
        ----
        rule (idstool.rule.Rule): The rule to be checked.

        Returns:
        -------
        list[dict]: A list of issues found in the rule. Each issue is typed as a `dict`.

        """

    def _add_checker_metadata(
        self: "CheckerInterface",
        issues: list[MutableMapping],
    ) -> Sequence[Mapping]:
        """Given a list of issues, return the same list with metadata from the checker."""
        name = self.__class__.__name__

        for issue in issues:
            issue["checker"] = name

        return issues
