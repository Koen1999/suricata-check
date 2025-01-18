"""`MandatoryChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import is_rule_option_set
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue


class MandatoryChecker(CheckerInterface):
    """The `MandatoryChecker` contains several checks based on the Suricata syntax that are critical.

    Codes M000-M009 report on missing mandatory rule options.
    """

    codes = {
        "M000": {"severity": logging.ERROR},
        "M001": {"severity": logging.ERROR},
    }

    def _check_rule(
        self: "MandatoryChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if not is_rule_option_set(rule, "msg"):
            issues.append(
                Issue(
                    code="M000",
                    message="The rule did not specify a msg, which is a mandatory field.",
                )
            )

        if not is_rule_option_set(rule, "sid"):
            issues.append(
                Issue(
                    code="M001",
                    message="The rule did not specify a sid, which is a mandatory field.",
                )
            )

        return issues
