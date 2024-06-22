"""`MsgChecker`."""

import logging
from collections.abc import Mapping, Sequence

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    is_rule_option_equal_to_regex,
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.regex import get_regex_provider
from suricata_check.utils.typing import ISSUES_TYPE, Issue

MSG_ALLOCATION: Mapping[str, Sequence[tuple[int, int]]] = {
    "local": [(1000000, 1999999)],
    "ET OPEN": [
        (2000000, 2103999),
        (2400000, 2609999),
    ],
    "ET": [(2700000, 2799999)],
    "ETPRO": [(2800000, 2899999)],
}

_regex_provider = get_regex_provider()

_S400_REGEX = _regex_provider.compile(
    r"""^"[A-Z0-9 ]+ [A-Z0-9]+ (?![A-Z0-9 ]+ ).*( .*)?"$"""
)
_MALWARE_REGEX = _regex_provider.compile(r"^.*(malware).*$", _regex_provider.IGNORECASE)
_S401_REGEX = _regex_provider.compile(r"""^".* [a-zA-Z0-9]+/[a-zA-Z0-9]+ .*"$""")
_VAGUE_KEYWORDS = ("possible", "unknown")
_S402_REGEX = _regex_provider.compile(
    r"^.*({}).*$".format("|".join(_VAGUE_KEYWORDS)), _regex_provider.IGNORECASE
)

_logger = logging.getLogger(__name__)


class MsgChecker(CheckerInterface):
    """The `MsgChecker` contains several checks based on the Suricata Msg allocation.

    Codes S400-S410 report on non-standard `msg` fields.
    """

    codes = (
        "S400",
        "S401",
        "S402",
    )

    def _check_rule(
        self: "MsgChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if is_rule_option_set(rule, "msg") and not is_rule_option_equal_to_regex(
            rule, "msg", _S400_REGEX
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
            and self.__desribes_malware(rule)
            and not is_rule_option_equal_to_regex(rule, "msg", _S401_REGEX)
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

        if is_rule_option_equal_to_regex(rule, "msg", _S402_REGEX):
            issues.append(
                Issue(
                    code="S402",
                    message="""\
The rule uses vague keywords such as possible or unknown in the msg field.
Consider rephrasing to provide a more clear message for interpreting generated alerts.\
""",
                ),
            )
        _logger.debug(_S402_REGEX.pattern)

        return issues

    @staticmethod
    def __desribes_malware(rule: idstools.rule.Rule) -> bool:
        if is_rule_suboption_set(rule, "metadata", "malware_family"):
            return True

        if is_rule_option_equal_to_regex(rule, "msg", _MALWARE_REGEX):
            return True

        _logger.debug("Rule does not describe malware: %s", rule["raw"])

        return False
