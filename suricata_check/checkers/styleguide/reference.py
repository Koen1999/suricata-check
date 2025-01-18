"""`ReferenceChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    is_rule_option_equal_to_regex,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import get_regex_provider

_regex_provider = get_regex_provider()

_S700_REGEX = _regex_provider.compile(
    r"^(?!url).*[A-Z]+.*$",
)
_S701_REGEX = _regex_provider.compile(
    r"^url,\s*https?.*$",
    _regex_provider.IGNORECASE,
)


class ReferenceChecker(CheckerInterface):
    """The `ReferenceChecker` contains several checks for Suricata reference option.

    Codes S700-710 report on non-standard usages of `reference`
    """

    codes = {
        "S700": {"severity": logging.INFO},
        "S701": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "ReferenceChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if is_rule_option_equal_to_regex(rule, "reference", _S700_REGEX):
            issues.append(
                Issue(
                    code="S700",
                    message="""\
The rule uses uppercase characters in the `reference` option.
Consider using only lowercase characters.\
""",
                ),
            )

        if is_rule_option_equal_to_regex(rule, "reference", _S701_REGEX):
            issues.append(
                Issue(
                    code="S701",
                    message="""\
The rule specifies the web protocol in the `reference` option.
Consider removing the protocol.\
""",
                ),
            )

        return issues
