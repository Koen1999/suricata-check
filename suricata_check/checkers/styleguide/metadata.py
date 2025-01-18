"""`MetadataChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue


class MetadataChecker(CheckerInterface):
    """The `MetadataChecker` contains several checks for Suricata metadata options.

    Codes S800-810 report on missing common `metadata` fields
    """

    codes = {
        "S800": {"severity": logging.INFO},
        "S801": {"severity": logging.INFO},
        "S802": {"severity": logging.INFO},
        "S803": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "MetadataChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if not is_rule_suboption_set(rule, "metadata", "attack_target"):
            issues.append(
                Issue(
                    code="S800",
                    message="""\
The rule did not specify the `attack_target` metadata option.
Consider specifying the `attack_target` metadata option to help analysts interpret alerts raised by this rule.\
""",
                ),
            )

        if not is_rule_suboption_set(rule, "metadata", "signature_severity") and not (
            is_rule_option_set(rule, "noalert")
            or is_rule_suboption_set(rule, "flowbits", "noalert")
        ):
            issues.append(
                Issue(
                    code="S801",
                    message="""\
The rule did not specify the `signature_severity` metadata option.
Consider specifying the `signature_severity` metadata option to help analysts interpret alerts raised by this rule.\
""",
                ),
            )

        if not is_rule_suboption_set(rule, "metadata", "performance_impact"):
            issues.append(
                Issue(
                    code="S802",
                    message="""\
The rule did not specify the `performance_impact` metadata option.
Consider specifying the `performance_impact` metadata option to help SOCs determine when to enable this rule.\
""",
                ),
            )

        if not is_rule_suboption_set(rule, "metadata", "deployment"):
            issues.append(
                Issue(
                    code="S803",
                    message="""\
The rule did not specify the `deployment` metadata option. \
Consider specifying the `deployment` metadata option to help SOCs determine when to enable this rule.\
""",
                ),
            )

        return issues
