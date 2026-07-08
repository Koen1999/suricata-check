"""`MandatoryChecker`."""

import logging
from types import MappingProxyType

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    get_rule_suboptions,
    is_rule_option_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import FLOW_OPTIONS
from suricata_check.utils.rule import Rule


class MandatoryChecker(CheckerInterface):
    """The `MandatoryChecker` contains several checks based on the Suricata syntax that are critical.

    Codes M000-M009 report on mandatory rule syntax violations.
    """

    codes = MappingProxyType(
        {
            "M000": {"severity": logging.ERROR},
            "M001": {"severity": logging.ERROR},
            "M002": {"severity": logging.ERROR},
        },
    )

    def _check_rule(
        self: "MandatoryChecker",
        rule: Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if not is_rule_option_set(rule, "msg"):
            issues.append(
                Issue(
                    code="M000",
                    message="The rule did not specify a msg, which is a mandatory field.",
                ),
            )

        if not is_rule_option_set(rule, "sid"):
            issues.append(
                Issue(
                    code="M001",
                    message="The rule did not specify a sid, which is a mandatory field.",
                ),
            )

        for suboption, _ in get_rule_suboptions(rule, "flow"):
            if suboption not in FLOW_OPTIONS:
                issues.append(
                    Issue(
                        code="M002",
                        message=f"""\
The rule uses invalid `flow` option: {suboption}.
Each `flow` suboption must be a valid Suricata flow option ({", ".join(FLOW_OPTIONS)}).\
""",
                    ),
                )

        return issues
