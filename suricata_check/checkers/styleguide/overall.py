"""`OverallChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    count_rule_options,
    get_all_variable_groups,
    get_rule_option,
    get_rule_sticky_buffer_naming,
    is_rule_option_equal_to,
    is_rule_option_equal_to_regex,
    is_rule_option_one_of,
    is_rule_option_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import (
    ALL_VARIABLES,
    CLASSTYPES,
    get_regex_provider,
)

_regex_provider = get_regex_provider()


# Regular expressions are placed here such that they are compiled only once.
# This has a significant impact on the performance.
_REGEX_S002a = _regex_provider.compile(
    r"^.*(EXPLOIT|CVE).*$",
    _regex_provider.IGNORECASE,
)
_REGEX_S002b = _regex_provider.compile(
    r"^.*(Internal|Inbound|Outbound).*$",
    _regex_provider.IGNORECASE,
)
_REGEX_S030 = _regex_provider.compile(r"^[a-z\-]+$")
_REGEX_S031 = _regex_provider.compile(r"^[^\|]*\|[^\|]*[A-Z]+[^\|]*\|[^\|]*$")


class OverallChecker(CheckerInterface):
    """The `OverallChecker` contains several the most basic checks for Suricata rules.

    Codes S000-S009 report on issues with the direction of the rule.

    Codes S010-S019 report on issues pertaining to the usage of non-standard options.

    Codes S020-S029 report on issues pertaining to the non-usage of recommended options.

    Codes S020-S029 report on issues pertaining to the non-usage of recommended options.

    Codes S031-S039 report on issues pertaining to the inappropriate usage of options.
    """

    codes = {
        "S000": {"severity": logging.INFO},
        "S001": {"severity": logging.INFO},
        "S002": {"severity": logging.INFO},
        "S010": {"severity": logging.INFO},
        "S011": {"severity": logging.INFO},
        "S012": {"severity": logging.INFO},
        "S013": {"severity": logging.INFO},
        "S014": {"severity": logging.INFO},
        "S020": {"severity": logging.INFO},
        "S021": {"severity": logging.INFO},
        "S030": {"severity": logging.INFO},
        "S031": {"severity": logging.INFO},
    }

    def _check_rule(  # noqa: C901
        self: "OverallChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if is_rule_option_equal_to(rule, "direction", "<->") or (
            is_rule_option_equal_to(rule, "source_addr", "any")
            and is_rule_option_equal_to(rule, "dest_addr", "any")
        ):
            issues.append(
                Issue(
                    code="S000",
                    message="""The rule did not specificy an inbound or outbound direction.
Consider constraining the rule to a specific direction such as INBOUND or OUTBOUND traffic.""",
                )
            )

        if is_rule_option_set(rule, "dns.query") and not is_rule_option_equal_to(
            rule,
            "dest_addr",
            "any",
        ):
            issues.append(
                Issue(
                    code="S001",
                    message="""The rule detects certain dns queries and has dest_addr not set to any \
causing the rule to be specific to either local or external resolvers.
Consider setting dest_addr to any.""",
                )
            )

        if (
            is_rule_option_equal_to_regex(rule, "msg", _REGEX_S002a)
            and not (
                is_rule_option_equal_to(rule, "source_addr", "any")
                and is_rule_option_equal_to(rule, "dest_addr", "any")
            )
            and not is_rule_option_equal_to_regex(rule, "msg", _REGEX_S002b)
        ):
            issues.append(
                Issue(
                    code="S002",
                    message="""The rule detects exploitation attempts in a constrained direction \
without specifying the direction in the rule msg. \
Consider setting `src_addr` and `dest_addr` to any to also account for lateral movement scenarios. \
Alternatively, you can specify the direction (i.e., `Internal` or `Inbound`) in the rule `msg`.""",
                )
            )

        # In the suricata style guide, this is mentioned as `packet_data`
        if is_rule_option_set(rule, "pkt_data"):
            issues.append(
                Issue(
                    code="S010",
                    message="""The rule uses the pkt_data option, \
which resets the inspection pointer resulting in confusing and disjoint logic.
Consider replacing the detection logic.""",
                )
            )

        if is_rule_option_set(rule, "priority"):
            issues.append(
                Issue(
                    code="S011",
                    message="""The rule uses priority option, which overrides operator tuning via classification.conf.
Consider removing the option.""",
                )
            )

        for sticky_buffer, modifier_alternative in get_rule_sticky_buffer_naming(rule):
            issues.append(
                Issue(
                    code="S012",
                    message=f"""The rule uses sticky buffer naming in the {sticky_buffer} option, which is complicated.
Consider using the {modifier_alternative} option instead.""",
                )
            )

        for variable_group in self.__get_invented_variable_groups(rule):
            issues.append(
                Issue(
                    code="S013",
                    message=f"""The rule uses a self-invented variable group ({variable_group}), \
which may be undefined in many environments.
Consider using the a standard variable group instead.""",
                )
            )

        if is_rule_option_set(rule, "classtype") and not is_rule_option_one_of(
            rule, "classtype", CLASSTYPES
        ):
            issues.append(
                Issue(
                    code="S014",
                    message=f"""The rule uses a self-invented classtype ({get_rule_option(rule, 'classtype')}), \
which may be undefined in many environments.
Consider using the a standard classtype instead.""",
                )
            )

        if not is_rule_option_set(rule, "content"):
            issues.append(
                Issue(
                    code="S020",
                    message="""The detection logic does not use the content option, \
which is can cause significant runtime overhead.
Consider adding a content match.""",
                )
            )

        if (
            not is_rule_option_set(rule, "fast_pattern")
            and count_rule_options(rule, "content") > 1
        ):
            issues.append(
                Issue(
                    code="S021",
                    message="""The rule has multiple content matches but does not use fast_pattern.
Consider assigning fast_pattern to the most unique content match.""",
                )
            )

        if is_rule_option_equal_to_regex(
            rule,
            "app-layer-protocol",
            _REGEX_S030,
        ):
            issues.append(
                Issue(
                    code="S030",
                    message="""The rule uses app-layer-protocol to assert the protocol.
Consider asserting this in the head instead using {} {} {} {} {} {} {}""".format(
                        get_rule_option(rule, "action"),
                        get_rule_option(rule, "app-layer-protocol"),
                        get_rule_option(rule, "source_addr"),
                        get_rule_option(rule, "source_port"),
                        get_rule_option(rule, "direction"),
                        get_rule_option(rule, "dest_addr"),
                        get_rule_option(rule, "dest_port"),
                    ),
                )
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            _REGEX_S031,
        ):
            issues.append(
                Issue(
                    code="S031",
                    message="The rule uses uppercase A-F in a hex content match.\nConsider using lowercase a-f instead.",
                )
            )

        return issues

    @staticmethod
    def __get_invented_variable_groups(rule: idstools.rule.Rule) -> list[str]:
        variable_groups = get_all_variable_groups(rule)

        invented_variable_groups = []

        for variable_group in variable_groups:
            if variable_group not in ALL_VARIABLES:
                invented_variable_groups.append(variable_group)

        return invented_variable_groups
