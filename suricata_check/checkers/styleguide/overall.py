# noqa: D100
from typing import Mapping, Sequence

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils import (
    ALL_VARIABLES,
    CLASSTYPES,
    count_rule_options,
    get_all_variable_groups,
    get_regex_provider,
    get_rule_option,
    get_rule_sticky_buffer_naming,
    is_rule_option_equal_to,
    is_rule_option_equal_to_regex,
    is_rule_option_one_of,
    is_rule_option_set,
)

regex_provider = get_regex_provider()


# Regular expressions are placed here such that they are compiled only once.
# This has a significant impact on the performance.
REGEX_S030 = regex_provider.compile(r"^[a-z\-]+$")
REGEX_S031 = regex_provider.compile(r"^[^\|]*\|[0-9A-Z\s]+\|[^\|]*$")


class OverallChecker(CheckerInterface):
    """The `OverallChecker` contains several the most basic checks for Suricata rules.

    Codes S000-S009 report on issues with the direction of the rule.
    Codes S010-S019 report on issues pertaining to the usage of non-standard options.
    Codes S020-S029 report on issues pertaining to the non-usage of recommended options.
    Codes S020-S029 report on issues pertaining to the non-usage of recommended options.
    Codes S031-S039 report on issues pertaining to the inappropriate usage of options.
    """

    codes = (
        "S000",
        "S001",
        "S010",
        "S011",
        "S012",
        "S013",
        "S014",
        "S020",
        "S021",
        "S030",
        "S031",
    )

    def check_rule(  # noqa: C901, D102
        self: "OverallChecker",
        rule: idstools.rule.Rule,
    ) -> Sequence[Mapping]:
        issues = []

        if is_rule_option_equal_to(rule, "direction", "<->") or (
            is_rule_option_equal_to(rule, "source_addr", "any")
            and is_rule_option_equal_to(rule, "dest_addr", "any")
        ):
            issues.append(
                {
                    "code": "S000",
                    "message": """The rule did not specificy an inbound or outbound direction.
Consider constraining the rule to a specific direction such as INBOUND or OUTBOUND traffic.""",
                },
            )

        if is_rule_option_set(rule, "dns.query") and not is_rule_option_equal_to(
            rule,
            "dest_addr",
            "any",
        ):
            issues.append(
                {
                    "code": "S001",
                    "message": """The rule detects certain dns queries and has dest_addr not set to any \
causing the rule to be specific to either local or external resolvers.
Consider setting dest_addr to any.""",
                },
            )

        if is_rule_option_set(rule, "packet_data"):
            issues.append(
                {
                    "code": "S010",
                    "message": """The rule uses the packet_data option, \
which resets the inspection pointer resulting in confusing and disjoint logic.
Consider replacing the detection logic.""",
                },
            )

        if is_rule_option_set(rule, "priority"):
            issues.append(
                {
                    "code": "S011",
                    "message": """The rule uses priority option, which overrides operator tuning via classification.conf.
Consider removing the option.""",
                },
            )

        for sticky_buffer, modifier_alternative in get_rule_sticky_buffer_naming(rule):
            issues.append(
                {
                    "code": "S012",
                    "message": f"""The rule uses sticky buffer naming in the {sticky_buffer} option, which is complicated.
Consider using the {modifier_alternative} option instead.""",
                },
            )

        for variable_group in self._get_invented_variable_groups(rule):
            issues.append(
                {
                    "code": "S013",
                    "message": f"""The rule uses a self-invented variable group ({variable_group}), \
which may be undefined in many environments.
Consider using the a standard variable group instead.""",
                },
            )

        if not is_rule_option_one_of(rule, "classtype", CLASSTYPES):
            issues.append(
                {
                    "code": "S014",
                    "message": f"""The rule uses a self-invented classtype ({get_rule_option(rule, 'classtype')}), \
which may be undefined in many environments.
Consider using the a standard classtype instead.""",
                },
            )

        if not is_rule_option_set(rule, "content"):
            issues.append(
                {
                    "code": "S020",
                    "message": """The detection logic does not use the content option, \
which is can cause significant runtime overhead.
Consider adding a content match.""",
                },
            )

        if (
            not is_rule_option_set(rule, "fast_pattern")
            and count_rule_options(rule, "content") > 1
        ):
            issues.append(
                {
                    "code": "S021",
                    "message": """The rule has multiple content matches but does not use fast_pattern.
Consider assigning fast_pattern to the most unique content match.""",
                },
            )

        if is_rule_option_equal_to_regex(
            rule,
            "app-layer-protocol",
            REGEX_S030,
        ):
            issues.append(
                {
                    "code": "S030",
                    "message": """The rule uses app-layer-protocol to assert the protocol.
Consider asserting this in the head instead using {} {} {} {} {} {} {}""".format(
                        get_rule_option(rule, "action"),
                        get_rule_option(rule, "app-layer-protocol"),
                        get_rule_option(rule, "source_addr"),
                        get_rule_option(rule, "source_port"),
                        get_rule_option(rule, "direction"),
                        get_rule_option(rule, "dest_addr"),
                        get_rule_option(rule, "dest_port"),
                    ),
                },
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            REGEX_S031,
        ):
            issues.append(
                {
                    "code": "S031",
                    "message": "The rule uses uppercase A-F in a hex content match.\nConsider using lowercase a-f instead.",
                },
            )

        return self._add_checker_metadata(issues)

    @staticmethod
    def _get_invented_variable_groups(rule: idstools.rule.Rule) -> list[str]:
        variable_groups = get_all_variable_groups(rule)

        invented_variable_groups = []

        for variable_group in variable_groups:
            if variable_group not in ALL_VARIABLES:
                invented_variable_groups.append(variable_group)

        return invented_variable_groups
