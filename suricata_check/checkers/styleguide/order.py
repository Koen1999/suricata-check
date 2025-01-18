"""`OrderChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    are_rule_options_put_before,
    count_rule_options,
    get_rule_keyword_sequences,
    get_rule_option_position,
    is_rule_option_always_put_before,
    is_rule_option_first,
    is_rule_option_put_before,
    is_rule_option_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import (
    ALL_DETECTION_KEYWORDS,
    ALL_TRANSFORMATION_KEYWORDS,
    BUFFER_KEYWORDS,
    CONTENT_KEYWORDS,
    FLOW_STREAM_KEYWORDS,
    MODIFIER_KEYWORDS,
    OTHER_PAYLOAD_KEYWORDS,
    PERFORMANCE_DETECTION_OPTIONS,
    POINTER_MOVEMENT_KEYWORDS,
    SIZE_KEYWORDS,
    TRANSFORMATION_KEYWORDS,
    get_regex_provider,
    get_rule_body,
)

_regex_provider = get_regex_provider()


# Regular expressions are placed here such that they are compiled only once.
# This has a significant impact on the performance.
REGEX_S210 = _regex_provider.compile(
    r"^\(.*content\s*:.*;\s*content\s*:.*;.*(depth|offset)\s*:.*\)$",
)


class OrderChecker(CheckerInterface):
    """The `OrderChecker` contains several checks on the ordering Suricata options.

    Note that the correct ordering of detection options is as follows:
        1. Buffer
        2. Size
        3. Transformation
        4. Coontent
        5. Pointer movement
        6. Fast pattern
        7. Nocase
        8. Other payload options

    Codes S200-S209 report on the non-standard ordering of common options.

    Codes S210-S219 report on the non-standard ordering of content matches.

    Codes S220-S229 report on the non-standard ordering of flow options.

    Codes S230-S239 report on the non-standard ordering of detection options.

    Codes S240-S249 report on the non-standard ordering of threshold options.
    """

    codes = {
        "S200": {"severity": logging.INFO},
        "S201": {"severity": logging.INFO},
        "S202": {"severity": logging.INFO},
        "S203": {"severity": logging.INFO},
        "S204": {"severity": logging.INFO},
        "S205": {"severity": logging.INFO},
        "S206": {"severity": logging.INFO},
        "S207": {"severity": logging.INFO},
        "S208": {"severity": logging.INFO},
        "S210": {"severity": logging.INFO},
        "S211": {"severity": logging.INFO},
        "S212": {"severity": logging.INFO},
        "S220": {"severity": logging.INFO},
        "S221": {"severity": logging.INFO},
        "S222": {"severity": logging.INFO},
        "S223": {"severity": logging.INFO},
        "S224": {"severity": logging.INFO},
        "S230": {"severity": logging.INFO},
        "S231": {"severity": logging.INFO},
        "S232": {"severity": logging.INFO},
        "S233": {"severity": logging.INFO},
        "S234": {"severity": logging.INFO},
        "S235": {"severity": logging.INFO},
        "S236": {"severity": logging.INFO},
        "S240": {"severity": logging.INFO},
        "S241": {"severity": logging.INFO},
    }

    def _check_rule(  # noqa: C901, PLR0912, PLR0915
        self: "OrderChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        body = get_rule_body(rule)

        if is_rule_option_first(rule, "msg") is not True:
            issues.append(
                Issue(
                    code="S200",
                    message="""The rule body does not have msg as the first option.
Consider reording to make msg the first option.""",
                )
            )

        if is_rule_option_put_before(rule, "reference", ("content", "pcre")) is True:
            issues.append(
                Issue(
                    code="S201",
                    message="""The rule body contains the reference option before the detection logic.
Consider reording to put the detection logic directly after the msg option.""",
                )
            )

        if is_rule_option_put_before(rule, "classtype", ("reference",)) is True:
            issues.append(
                Issue(
                    code="S202",
                    message="""The rule body contains the classtype option before the reference option.
Consider reording to put the classtype option directly after the reference option.""",
                )
            )

        if is_rule_option_put_before(rule, "classtype", ("content", "pcre")) is True:
            issues.append(
                Issue(
                    code="S203",
                    message="""The rule body contains the classtype option before the detection logic.
Consider reording to put the classtype option directly after the detection logic.""",
                )
            )

        if is_rule_option_put_before(rule, "sid", ("classtype",)) is True:
            issues.append(
                Issue(
                    code="S204",
                    message="""The rule body contains the sid option before the classtype option.
Consider reording to put the sid option directly after the classtype option.""",
                )
            )

        if is_rule_option_put_before(rule, "sid", ("reference",)) is True:
            issues.append(
                Issue(
                    code="S205",
                    message="""The rule body contains the sid option before the reference option.
Consider reording to put the sid option directly after the reference option.""",
                )
            )

        if is_rule_option_put_before(rule, "sid", ("content", "pcre")) is True:
            issues.append(
                Issue(
                    code="S206",
                    message="""The rule body contains the sid option before the detection logic.
Consider reording to put the sid option directly after the detection logic.""",
                )
            )

        if is_rule_option_put_before(rule, "rev", ("sid",)) is True:
            issues.append(
                Issue(
                    code="S207",
                    message="""The rule body contains the rev option before the sid option.
Consider reording to put the rev option directly after the sid option.""",
                )
            )

        if is_rule_option_put_before(rule, "metadata", ("sid", "rev")) is True:
            issues.append(
                Issue(
                    code="S208",
                    message="""The rule body contains does not have the metadata option as the last option.
Consider making metadata the last option.""",
                )
            )

        if (
            REGEX_S210.match(
                body,
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S210",
                    message="""The rule body contains a content matches modified by depth or offset \
that is not the first content match.
Consider moving the modified content match to the beginning of the detection options.""",
                )
            )

        if count_rule_options(rule, "depth") > 1:
            issues.append(
                Issue(
                    code="S211",
                    message="""The rule body contains more than one content matche modified by depth.
Consider making the second content match relative to the first using the within option.""",
                )
            )

        if count_rule_options(rule, "offset") > 1:
            issues.append(
                Issue(
                    code="S212",
                    message="""The rule body contains more than one content matche modified by offset.
Consider making the second content match relative to the first using the distance option.""",
                )
            )

        if (
            is_rule_option_set(rule, "flow")
            and get_rule_option_position(rule, "flow") != 1
        ):
            issues.append(
                Issue(
                    code="S220",
                    message="""The rule flow option is set but not directly following the msg option.
Consider moving the flow option to directly after the msg option.""",
                )
            )

        if (
            is_rule_option_always_put_before(
                rule,
                "flow",
                FLOW_STREAM_KEYWORDS,
            )
            is False
        ):
            issues.append(
                Issue(
                    code="S221",
                    message="""The rule contains flow or stream keywords before the flow option in the rule body.
Consider moving the flow option to before the flow and/or stream keywords.""",
                )
            )

        if (
            are_rule_options_put_before(
                rule,
                ("content", "pcre"),
                FLOW_STREAM_KEYWORDS,
            )
            is True
        ):
            issues.append(
                Issue(
                    code="S222",
                    message="""The rule contains flow or stream keywords after content buffers or detection logic.
Consider moving the flow and/or stream keywords to before content buffers and detection options.""",
                )
            )

        if (
            is_rule_option_put_before(
                rule,
                "urilen",
                FLOW_STREAM_KEYWORDS,
            )
            is True
        ):
            issues.append(
                Issue(
                    code="S223",
                    message="""The rule contains the urilen option before the flow or stream keywords in the rule body.
Consider moving the urilen option to after the flow and/or stream keywords.""",
                )
            )

        if (
            is_rule_option_always_put_before(
                rule,
                "urilen",
                ("content", "pcre"),
            )
            is False
        ):
            issues.append(
                Issue(
                    code="S224",
                    message="""The rule contains the urilen option after content buffers or detection logic.
Consider moving the urilen option to before content buffers and detection options.""",
                )
            )

        # Detects pointer movement before any content or buffer option or between a buffer and a content option.
        for sequence in get_rule_keyword_sequences(
            rule, seperator_keywords=CONTENT_KEYWORDS
        ):
            if (
                are_rule_options_put_before(
                    rule,
                    POINTER_MOVEMENT_KEYWORDS,
                    set(CONTENT_KEYWORDS).union(BUFFER_KEYWORDS),
                    sequence=sequence,
                )
                is True
            ):
                issues.append(
                    Issue(
                        code="S230",
                        message="""The rule contains pointer movement before the content option in sequence {}.
Consider moving the pointer movement options to after the content option.""".format(
                            sequence
                        ),
                    )
                )

        # Detects fast_pattern before any content or buffer option or between a buffer and a content option.
        for sequence in get_rule_keyword_sequences(
            rule, seperator_keywords=CONTENT_KEYWORDS
        ):
            if (
                is_rule_option_put_before(
                    rule,
                    "fast_pattern",
                    set(SIZE_KEYWORDS)
                    .union(ALL_TRANSFORMATION_KEYWORDS)
                    .union(CONTENT_KEYWORDS)
                    .union(POINTER_MOVEMENT_KEYWORDS),
                    sequence=sequence,
                )
                is True
            ):
                issues.append(
                    Issue(
                        code="S231",
                        message="""The rule contains the fast_pattern option before \
size options, transformation options, the content option or pointer movement options in sequence {}.
Consider moving the fast_pattern option to after \
size options, transformation options, the content option or pointer movement options.""".format(
                            sequence
                        ),
                    )
                )

        # Detects no_case before any content or buffer option or between a buffer and a content option.
        for sequence in get_rule_keyword_sequences(
            rule, seperator_keywords=CONTENT_KEYWORDS
        ):
            if (
                is_rule_option_put_before(
                    rule,
                    "nocase",
                    set(SIZE_KEYWORDS)
                    .union(ALL_TRANSFORMATION_KEYWORDS)
                    .union(CONTENT_KEYWORDS)
                    .union(POINTER_MOVEMENT_KEYWORDS)
                    .union(PERFORMANCE_DETECTION_OPTIONS),
                    sequence=sequence,
                )
                is True
            ):
                issues.append(
                    Issue(
                        code="S232",
                        message="""The rule contains the nocase option before \
size options, transformation options, the content option, pointer movement options, or fast_pattern option in sequence {}.
Consider moving the nocase option to after \
size options, transformation options, the content option, pointer movement options, or fast_pattern option.""".format(
                            sequence
                        ),
                    )
                )

        # Detects modifier options before any content or buffer option or between a buffer and a content option.
        for sequence in get_rule_keyword_sequences(
            rule, seperator_keywords=CONTENT_KEYWORDS
        ):
            if (
                are_rule_options_put_before(
                    rule,
                    MODIFIER_KEYWORDS,
                    set(CONTENT_KEYWORDS),
                    sequence=sequence,
                )
                is True
            ):
                issues.append(
                    Issue(
                        code="S233",
                        message="""The rule contains modifier options before the content option.
Consider moving the modifier options to after the content option.""",
                    )
                )

        # Detects other detection options before any content or buffer option or between a buffer and a content option.
        for sequence in get_rule_keyword_sequences(
            rule, seperator_keywords=CONTENT_KEYWORDS
        ):
            if (
                are_rule_options_put_before(
                    rule,
                    OTHER_PAYLOAD_KEYWORDS,
                    set(CONTENT_KEYWORDS).union(BUFFER_KEYWORDS),
                    sequence=sequence,
                )
                is True
            ):
                issues.append(
                    Issue(
                        code="S234",
                        message="""The rule contains other detection options before \
size options, transformation options, the content option, pointer movement options, nocase option, or fast_pattern option.
Consider moving the other detection options to after \
size options, transformation options,  the content option, pointer movement options, nocase option, or fast_pattern option.""",
                    )
                )

        # Detects size options after any transformation options, content option or other detection options.
        for sequence in get_rule_keyword_sequences(
            rule, seperator_keywords=CONTENT_KEYWORDS
        ):
            if (
                are_rule_options_put_before(
                    rule,
                    set(TRANSFORMATION_KEYWORDS)
                    .union(CONTENT_KEYWORDS)
                    .union(OTHER_PAYLOAD_KEYWORDS),
                    SIZE_KEYWORDS,
                    sequence=sequence,
                )
                is True
            ):
                issues.append(
                    Issue(
                        code="S235",
                        message="""The rule contains other size options after \
any transformation options, content option or other detection options.
Consider moving the size options to after any transformation options, content option or other detection options""",
                    )
                )

        # Detects transformation options after any content option or other detection options.
        for sequence in get_rule_keyword_sequences(
            rule, seperator_keywords=CONTENT_KEYWORDS
        ):
            if (
                are_rule_options_put_before(
                    rule,
                    set(CONTENT_KEYWORDS).union(OTHER_PAYLOAD_KEYWORDS),
                    TRANSFORMATION_KEYWORDS,
                    sequence=sequence,
                )
                is True
            ):
                issues.append(
                    Issue(
                        code="S236",
                        message="""The rule contains other transformation options after \
any content option or other detection options.
Consider moving the transformation options to after any content option or other detection options""",
                    )
                )

        if (
            is_rule_option_put_before(
                rule,
                "threshold",
                ALL_DETECTION_KEYWORDS,
            )
            is True
        ):
            issues.append(
                Issue(
                    code="S240",
                    message="""The rule contains the threshold option before some detection option.
Consider moving the threshold option to after the detection options.""",
                )
            )

        if (
            is_rule_option_always_put_before(
                rule,
                "threshold",
                ("reference", "sid"),
            )
            is False
        ):
            issues.append(
                Issue(
                    code="S241",
                    message="""The rule contains the threshold option after the reference and/or sid option.
Consider moving the threshold option to before the reference and sid options.""",
                )
            )

        return issues
