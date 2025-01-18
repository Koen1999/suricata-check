"""`MsgChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    get_rule_option,
    is_rule_option_equal_to_regex,
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import get_regex_provider

_regex_provider = get_regex_provider()

_S400_REGEX = _regex_provider.compile(r"""^"[A-Z0-9 ]+ [A-Z0-9_]+ .*"$""")
_MALWARE_REGEX = _regex_provider.compile(r"^.*(malware).*$", _regex_provider.IGNORECASE)
_S401_REGEX = _regex_provider.compile(r"""^".* [a-zA-Z0-9]+/[a-zA-Z0-9]+ .*"$""")
_VAGUE_KEYWORDS = ("possible", "unknown")
_S402_REGEX = _regex_provider.compile(
    r"^.*({}).*$".format("|".join(_VAGUE_KEYWORDS)), _regex_provider.IGNORECASE
)
_UNDESIRABLE_DATE_REGEXES = (
    _regex_provider.compile(r"^.*(\d{4}/\d{2}/\d{2}).*$", _regex_provider.IGNORECASE),
    _regex_provider.compile(r"^.*(\d{4}-[2-9]\d-\d{2}).*$", _regex_provider.IGNORECASE),
)  # Desirable format is ISO (YYYY-MM-DD)
_S404_REGEX = _regex_provider.compile(
    r"^.*(C2|C&C|Command and Control|Command & Control).*$", _regex_provider.IGNORECASE
)
_S405_REGEX = _regex_provider.compile(
    r"^.*(Go|MSIL|ELF64|MSIL|JS|Win32|DOS|Amiga|C64|Plan9).*$",
    _regex_provider.IGNORECASE,
)
_S406_REGEX = _regex_provider.compile(
    r"^.*((\w+\.)+[a-z]{2,}).*$",
    _regex_provider.IGNORECASE,
)
_S407_REGEX = _regex_provider.compile(
    r"^.*((\w+\[\.\])+[a-z]{2,}).*$",
    _regex_provider.IGNORECASE,
)
_S408_REGEX = _regex_provider.compile(
    r"^.*((\w+\. )+[a-z]{2,}).*$",
    _regex_provider.IGNORECASE,
)

_logger = logging.getLogger(__name__)


class MsgChecker(CheckerInterface):
    """The `MsgChecker` contains several checks based for the Msg option in Suricata rules.

    Codes S400-S410 report on non-standard `msg` fields.
    """

    codes = {
        "S400": {"severity": logging.INFO},
        "S401": {"severity": logging.INFO},
        "S402": {"severity": logging.INFO},
        "S403": {"severity": logging.INFO},
        "S404": {"severity": logging.INFO},
        "S405": {"severity": logging.INFO},
        "S406": {"severity": logging.WARNING},
        "S407": {"severity": logging.INFO},
        "S408": {"severity": logging.INFO},
        "S409": {"severity": logging.INFO},
    }

    def _check_rule(  # noqa: C901
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

        if not (
            is_rule_option_set(rule, "noalert")
            or is_rule_suboption_set(rule, "flowbits", "noalert")
        ) and is_rule_option_equal_to_regex(rule, "msg", _S402_REGEX):
            issues.append(
                Issue(
                    code="S402",
                    message="""\
The rule uses vague keywords such as possible or unknown in the msg field.
Consider rephrasing to provide a more clear message for interpreting generated alerts.\
""",
                ),
            )

        for regex in _UNDESIRABLE_DATE_REGEXES:
            if is_rule_option_equal_to_regex(rule, "msg", regex):
                issues.append(
                    Issue(
                        code="S403",
                        message="""\
The rule uses a non-ISO date in the msg field.
Consider reformatting the date to ISO format (YYYY-MM-DD).\
""",
                    ),
                )
                break

        if is_rule_option_equal_to_regex(rule, "msg", _S404_REGEX):
            issues.append(
                Issue(
                    code="S404",
                    message="""\
The rule uses a different way of writing CnC (Command & Control) in the msg field.
Consider writing CnC instead.\
""",
                ),
            )

        if self.__desribes_malware(rule) and not is_rule_option_equal_to_regex(
            rule, "msg", _S405_REGEX
        ):
            issues.append(
                Issue(
                    code="S405",
                    message="""\
The rule likely detects malware but does not specify the file type in the msg field.
Consider specifying a file type such as `DOS` or `ELF64`.\
""",
                ),
            )

        if is_rule_option_equal_to_regex(rule, "msg", _S406_REGEX):
            issues.append(
                Issue(
                    code="S406",
                    message="""\
The rule specifies a domain name without escaping the label seperators.
Consider escaping the domain names by putting a space before the dot like `foo .bar` to prevent information leaks.\
""",
                ),
            )

        if is_rule_option_equal_to_regex(rule, "msg", _S407_REGEX):
            issues.append(
                Issue(
                    code="S407",
                    message="""\
The rule specifies a domain name and escapes it in a non-standard way in the msg field.
Consider escaping the domain names by putting a space before the dot like `foo .bar`.\
""",
                ),
            )

        if is_rule_option_equal_to_regex(rule, "msg", _S408_REGEX):
            issues.append(
                Issue(
                    code="S408",
                    message="""\
The rule specifies a domain name and escapes it in a non-standard way in the msg field.
Consider escaping the domain names by putting a space before the dot like `foo .bar`.\
""",
                ),
            )

        # Note that all characters under 128 are ASCII
        if is_rule_option_set(rule, "msg") and any(
            ord(c) > 128  # noqa: PLR2004
            for c in get_rule_option(rule, "msg")  # type: ignore reportOptionalIterable
        ):
            issues.append(
                Issue(
                    code="S409",
                    message="""\
The rule uses non-ASCII characters in the msg field.
Consider removing non-ASCII characters.\
""",
                ),
            )

        return issues

    @staticmethod
    def __desribes_malware(rule: idstools.rule.Rule) -> bool:
        if is_rule_suboption_set(rule, "metadata", "malware_family"):
            return True

        if is_rule_option_equal_to_regex(rule, "msg", _MALWARE_REGEX):
            return True

        _logger.debug("Rule does not describe malware: %s", rule["raw"])

        return False
