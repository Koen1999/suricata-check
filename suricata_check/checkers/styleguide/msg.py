# noqa: D100
import logging
from collections.abc import Mapping, Sequence

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    get_rule_option,
    is_rule_option_equal_to_regex,
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.regex import get_regex_provider
from suricata_check.utils.typing import ISSUES_TYPE, Issue

Msg_ALLOCATION: Mapping[str, Sequence[tuple[int, int]]] = {
    "local": [(1000000, 1999999)],
    "ET OPEN": [
        (2000000, 2103999),
        (2400000, 2609999),
    ],
    "ET": [(2700000, 2799999)],
    "ETPRO": [(2800000, 2899999)],
}

regex_provider = get_regex_provider()

S400_REGEX = regex_provider.compile(
    r"""^"[A-Z0-9 ]+ [A-Z0-9]+ (?![A-Z0-9 ]+ ).*( .*)?"$"""
)
MALWARE_REGEX = regex_provider.compile(r"^.*(malware).*$")
S401_REGEX = regex_provider.compile(r"""^".* [a-zA-Z0-9]+/[a-zA-Z0-9]+ .*"$""")

logger = logging.getLogger(__name__)


class MsgChecker(CheckerInterface):
    """The `MsgChecker` contains several checks based on the Suricata Msg allocation.

    Codes S400-S410 report on non-standard `msg` fields.
    """

    codes = (
        "S400",
        "S401",
    )

    def _check_rule(
        self: "MsgChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if is_rule_option_set(rule, "msg") and not is_rule_option_equal_to_regex(
            rule, "msg", S400_REGEX
        ):
            issues.append(
                Issue(
                    code="S400",
                    message="""\
The rule has a non-standard format for the msg field.
Consider changing the msg field to `RULESET CATEGORY Description`.\
""",
                ),
            )

        if (
            is_rule_option_set(rule, "msg")
            and self._desribes_malware(rule)
            and not is_rule_option_equal_to_regex(rule, "msg", S400_REGEX)
        ):
            issues.append(
                Issue(
                    code="S401",
                    message="""\
The rule describes malware but does not specify the paltform or malware family in the msg field.
Consider changing the msg field to include `Platform/malfamily`.\
""",
                ),
            )

        return issues

    @staticmethod
    def _desribes_malware(rule: idstools.rule.Rule) -> bool:
        if is_rule_suboption_set(rule, "metadata", "malware_family"):
            return True

        if is_rule_option_equal_to_regex(rule, "msg", MALWARE_REGEX):
            return True

        return False
