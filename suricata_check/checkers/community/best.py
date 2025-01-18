"""`BestChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    get_rule_option,
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue


class BestChecker(CheckerInterface):
    """The `BestChecker` contains several checks for best practices to improve the experience of Suricata rules for everyone.

    Codes C100-C110 report on missing fields that should be set.
    """

    codes = {
        "C100": {"severity": logging.INFO},
        "C101": {"severity": logging.INFO},
        "C102": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "BestChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if not (
            is_rule_option_set(rule, "noalert")
            or is_rule_suboption_set(rule, "flowbits", "noalert")
        ) and not is_rule_option_set(rule, "target"):
            issues.append(
                Issue(
                    code="C100",
                    message="""\
The rule does not use the `target` Suricata meta option.
Consider adding the `target` option to specify which IP address is the target of the attack.\
""",
                ),
            )

        if not is_rule_suboption_set(rule, "metadata", "created_at"):
            issues.append(
                Issue(
                    code="C101",
                    message="""\
The rule does not use set the `created_at` metadata option.
Consider adding the `created_at` metadata option to inform users of the recency of this signature.\
""",
                ),
            )

        if (
            is_rule_option_set(rule, "rev")
            and int(get_rule_option(rule, "rev")) > 1  # type: ignore reportArgumentType
            and not is_rule_suboption_set(rule, "metadata", "updated_at")
        ):
            issues.append(
                Issue(
                    code="C102",
                    message="""\
The rule does not use set the `updated_at` metadata option while it has been revised since creation.
Consider adding the `updated_at` metadata option to inform users of the recency of this signature.\
""",
                ),
            )

        return issues
