"""`PcreChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    is_rule_option_equal_to_regex,
    is_rule_option_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import get_regex_provider

_regex_provider = get_regex_provider()

_S601_REGEX = _regex_provider.compile(
    r"^.*(\.\*).*$",
    _regex_provider.IGNORECASE,
)


class PcreChecker(CheckerInterface):
    """The `PcreChecker` contains several checks for Suricata PCRE options.

    Codes S600-610 report on unrecommended usages of `pcre`
    """

    codes = {"S600": {"severity": logging.INFO}, "S601": {"severity": logging.INFO}}

    def _check_rule(
        self: "PcreChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if is_rule_option_set(rule, "pcre") and not is_rule_option_set(rule, "content"):
            issues.append(
                Issue(
                    code="S600",
                    message="""\
The rule uses the `pcre` option but has no `content` option set.
Consider using the content option atleast once to anchor and improve runtime performance.\
""",
                ),
            )

        if is_rule_option_set(rule, "pcre") and is_rule_option_equal_to_regex(
            rule, "pcre", _S601_REGEX
        ):
            issues.append(
                Issue(
                    code="S601",
                    message="""\
The rule uses the `pcre` with an unlimited inspection depth.
Consider limiting the inspection depth to improve runtime performance.\
""",
                ),
            )

        return issues
