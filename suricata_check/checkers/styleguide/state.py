"""`StateChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    get_rule_suboptions,
    is_rule_option_always_equal_to_regex,
    is_rule_option_always_put_before,
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import get_regex_provider

_regex_provider = get_regex_provider()

_S510_REGEX = _regex_provider.compile(
    r"^((set|isset|toggle|unset|isnotset),[A-Z]+\.\w+)|(noalert)$",
    _regex_provider.IGNORECASE,
)

_S520_REGEX = _regex_provider.compile(
    r"^((set|isset|toggle|unset|isnotset),[A-Z]+\.\w+)|(noalert),.*$",
    _regex_provider.IGNORECASE,
)

_logger = logging.getLogger(__name__)


class StateChecker(CheckerInterface):
    """The `StateChecker` contains several checks for Suricata options relating to the connection or detection state.

    Codes S500-S510 report on non-standard usages of `flow`
    Codes S510-S520 report on non-standard usages of `flowbits`
    Codes S520-S530 report on non-standard usages of `xbits`
    """

    codes = {
        "S500": {"severity": logging.INFO},
        "S501": {"severity": logging.INFO},
        "S510": {"severity": logging.INFO},
        "S511": {"severity": logging.INFO},
        "S520": {"severity": logging.INFO},
        "S521": {"severity": logging.INFO},
        "S522": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "StateChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if is_rule_option_set(rule, "flow") and not is_rule_option_always_put_before(
            rule,
            "established",
            ["to_server", "to_client", "from_server", "from_client"],
            sequence=[suboption[0] for suboption in get_rule_suboptions(rule, "flow")],
        ):
            issues.append(
                Issue(
                    code="S500",
                    message="""\
The rule specifies the connection state after the connection direction in the `flow` option.
Consider specifying the connection state first like `established,to_server`.\
""",
                ),
            )

        if is_rule_suboption_set(rule, "flow", "from_client") or is_rule_suboption_set(
            rule, "flow", "from_server"
        ):
            issues.append(
                Issue(
                    code="S501",
                    message="""\
The rule has set `from_client` or `from_server` as a `flow` option.
Consider using `to_client` or `to_server` instead.\
""",
                ),
            )

        if is_rule_option_always_equal_to_regex(rule, "flowbits", _S510_REGEX) is False:
            issues.append(
                Issue(
                    code="S510",
                    message="""\
The rule sets flowbits with a non-standard name.
Consider using `RULESET.description` as name for the flowbit.\
""",
                ),
            )

        if (
            (
                is_rule_suboption_set(rule, "flowbits", "set")
                or is_rule_suboption_set(rule, "flowbits", "unset")
            )
            and not (
                is_rule_suboption_set(rule, "flowbits", "isset")
                or is_rule_suboption_set(rule, "flowbits", "isnotset")
            )
            and not (
                is_rule_option_set(rule, "noalert")
                or is_rule_suboption_set(rule, "flowbits", "noalert")
            )
        ):
            issues.append(
                Issue(
                    code="S511",
                    message="""\
The rule (un)sets a flowbit but does not use the noalert option.
Consider using the noalert option to prevent unnecessary alerts.\
""",
                ),
            )

        if is_rule_option_always_equal_to_regex(rule, "xbits", _S520_REGEX) is False:
            issues.append(
                Issue(
                    code="S520",
                    message="""\
The rule sets xbits with a non-standard name.
Consider using `RULESET.description` as name for the xbit.\
""",
                ),
            )

        if (
            (
                is_rule_suboption_set(rule, "xbits", "set")
                or is_rule_suboption_set(rule, "xbits", "unset")
            )
            and not is_rule_option_set(rule, "noalert")
            and not (
                is_rule_suboption_set(rule, "xbits", "isset")
                or is_rule_suboption_set(rule, "xbits", "isnotset")
            )
        ):
            issues.append(
                Issue(
                    code="S521",
                    message="""\
The rule (un)sets a xbit but does not use the noalert option.
Consider using the noalert option to prevent unnecessary alerts.\
""",
                ),
            )

        if (is_rule_suboption_set(rule, "xbits", "set")) and not is_rule_suboption_set(
            rule, "xbits", "expire"
        ):
            issues.append(
                Issue(
                    code="S522",
                    message="""\
The rule sets a xbit but does not explcitly set the expire option.
Consider setting the expire option to indicate for how long the xbit remains relevant.\
""",
                ),
            )

        return issues
