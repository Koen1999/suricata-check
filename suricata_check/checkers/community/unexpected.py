"""`UnexpectedChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue


class UnexpectedChecker(CheckerInterface):
    """The `UnexpectedChecker` contains several checks for unexpected Suricata behavior that users may not anticipate.

    Codes C000-C010 report on unexpected behavior.
    """

    codes = {
        "C000": {"severity": logging.WARNING},
    }

    def _check_rule(
        self: "UnexpectedChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if (
            is_rule_suboption_set(rule, "flowbits", "set")
            or is_rule_suboption_set(rule, "xbits", "set")
        ) and (is_rule_option_set(rule, "threshold")):
            issues.append(
                Issue(
                    code="C000",
                    message="""\
The rule uses the Suricata threshold option in combination with the setting of flowbits or xbits.
Note that the flowbit or xbit will be set on every match regardless of whether the threshold is reached.
Consider removing the `threshold` option from the rule to prevent confusion.\
""",
                ),
            )

        return issues
