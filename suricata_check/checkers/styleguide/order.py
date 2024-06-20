# noqa: D100
import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    are_rule_options_put_before,
    count_rule_options,
    get_rule_option_position,
    is_rule_option_always_put_before,
    is_rule_option_first,
    is_rule_option_last,
    is_rule_option_put_before,
    is_rule_option_set,
)
from suricata_check.utils.regex import (
    ALL_DETECTION_KEYWORDS,
    ALL_MODIFIER_KEYWORDS,
    ALL_TRANSFORMATION_KEYWORDS,
    BUFFER_KEYWORDS,
    CONTENT_KEYWORDS,
    FLOW_STREAM_KEYWORDS,
    MATCH_LOCATION_KEYWORDS,
    OTHER_PAYLOAD_KEYWORDS,
    POINTER_MOVEMENT_KEYWORDS,
    SIZE_KEYWORDS,
    get_options_regex,
    get_regex_provider,
    get_rule_body,
)
from suricata_check.utils.typing import ISSUES_TYPE

regex_provider = get_regex_provider()


# Regular expressions are placed here such that they are compiled only once.
# This has a significant impact on the performance.
REGEX_S210 = regex_provider.compile(
    r"^\(.*content\s*:.*;\s*content\s*:.*;.*(depth|offset)\s*:.*\)$",
)
REGEX_S230 = regex_provider.compile(
    rf"^\(((?!{get_options_regex(CONTENT_KEYWORDS).pattern}).*|{get_options_regex(BUFFER_KEYWORDS).pattern})(?!{get_options_regex(CONTENT_KEYWORDS).pattern}).*{get_options_regex(POINTER_MOVEMENT_KEYWORDS).pattern}.*{get_options_regex(CONTENT_KEYWORDS).pattern}.*\)$",
)
REGEX_S231 = regex_provider.compile(
    r"^\(((?!{}).*|{})(?!{}).*{}.*{}.*\)$".format(
        get_options_regex(CONTENT_KEYWORDS).pattern,
        get_options_regex(BUFFER_KEYWORDS).pattern,
        get_options_regex(CONTENT_KEYWORDS).pattern,
        "fast_pattern",
        get_options_regex(
            set(SIZE_KEYWORDS)
            .union(ALL_TRANSFORMATION_KEYWORDS)
            .union(CONTENT_KEYWORDS)
            .union(POINTER_MOVEMENT_KEYWORDS),
        ).pattern,
    ),
)
REGEX_S232 = regex_provider.compile(
    r"^\(((?!{}).*|{})(?!{}).*{}.*{}.*\)$".format(
        get_options_regex(CONTENT_KEYWORDS).pattern,
        get_options_regex(BUFFER_KEYWORDS).pattern,
        get_options_regex(CONTENT_KEYWORDS).pattern,
        "nocase",
        get_options_regex(
            set(SIZE_KEYWORDS)
            .union(ALL_TRANSFORMATION_KEYWORDS)
            .union(CONTENT_KEYWORDS)
            .union(POINTER_MOVEMENT_KEYWORDS)
            .union(("fast_pattern",)),
        ).pattern,
    ),
)
REGEX_S233 = regex_provider.compile(
    rf"^\(((?!{get_options_regex(CONTENT_KEYWORDS).pattern}).*|{get_options_regex(BUFFER_KEYWORDS).pattern})(?!{get_options_regex(CONTENT_KEYWORDS).pattern}).*{get_options_regex(ALL_MODIFIER_KEYWORDS).pattern}.*{get_options_regex(CONTENT_KEYWORDS).pattern}.*\)$",
)
REGEX_S234 = regex_provider.compile(
    r"^\(((?!{}).*|{})(?!{}).*{}.*{}.*\)$".format(
        get_options_regex(CONTENT_KEYWORDS).pattern,
        get_options_regex(BUFFER_KEYWORDS).pattern,
        get_options_regex(CONTENT_KEYWORDS).pattern,
        get_options_regex(
            set(MATCH_LOCATION_KEYWORDS).union(OTHER_PAYLOAD_KEYWORDS),
        ).pattern,
        get_options_regex(
            set(SIZE_KEYWORDS)
            .union(ALL_TRANSFORMATION_KEYWORDS)
            .union(CONTENT_KEYWORDS)
            .union(POINTER_MOVEMENT_KEYWORDS)
            .union(("nocase", "fast_pattern")),
        ).pattern,
    ),
)
REGEX_S235 = regex_provider.compile(
    r"^\(.*{}(?!{}).*{}.*\)$".format(
        get_options_regex(
            set(ALL_TRANSFORMATION_KEYWORDS)
            .union(CONTENT_KEYWORDS)
            .union(OTHER_PAYLOAD_KEYWORDS),
        ).pattern,
        get_options_regex(BUFFER_KEYWORDS).pattern,
        get_options_regex(SIZE_KEYWORDS).pattern,
    ),
)
REGEX_S236 = regex_provider.compile(
    r"^\(.*{}(?!{}).*{}.*\)$".format(
        get_options_regex(
            set(CONTENT_KEYWORDS).union(OTHER_PAYLOAD_KEYWORDS),
        ).pattern,
        get_options_regex(BUFFER_KEYWORDS).pattern,
        get_options_regex(ALL_TRANSFORMATION_KEYWORDS).pattern,
    ),
)


class OrderChecker(CheckerInterface):
    """The `OrderChecker` contains several checks based on the Suricata syntax that are critical.

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

    codes = (
        "S200",
        "S201",
        "S202",
        "S203",
        "S204",
        "S205",
        "S206",
        "S207",
        "S208",
        "S210",
        "S211",
        "S212",
        "S220",
        "S221",
        "S222",
        "S223",
        "S224",
        "S230",
        "S231",
        "S233",
        "S234",
        "S235",
        "S240",
        "S241",
    )

    def check_rule(  # noqa: C901, PLR0912, D102, PLR0915
        self: "OrderChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues = []

        body = get_rule_body(rule)

        if is_rule_option_first(rule, "msg") is not True:
            issues.append(
                {
                    "code": "S200",
                    "message": """The rule body does not have msg as the first option.
Consider reording to make msg the first option.""",
                },
            )

        if is_rule_option_put_before(rule, "reference", ("content", "pcre")) is True:
            issues.append(
                {
                    "code": "S201",
                    "message": """The rule body contains the reference option before the detection logic.
Consider reording to put the detection logic directly after the msg option.""",
                },
            )

        if is_rule_option_put_before(rule, "classtype", ("reference",)) is True:
            issues.append(
                {
                    "code": "S202",
                    "message": """The rule body contains the classtype option before the reference option.
Consider reording to put the classtype option directly after the reference option.""",
                },
            )

        if is_rule_option_put_before(rule, "classtype", ("content", "pcre")) is True:
            issues.append(
                {
                    "code": "S203",
                    "message": """The rule body contains the classtype option before the detection logic.
Consider reording to put the classtype option directly after the detection logic.""",
                },
            )

        if is_rule_option_put_before(rule, "sid", ("classtype",)) is True:
            issues.append(
                {
                    "code": "S204",
                    "message": """The rule body contains the sid option before the classtype option.
Consider reording to put the sid option directly after the classtype option.""",
                },
            )

        if is_rule_option_put_before(rule, "sid", ("reference",)) is True:
            issues.append(
                {
                    "code": "S205",
                    "message": """The rule body contains the sid option before the reference option.
Consider reording to put the sid option directly after the reference option.""",
                },
            )

        if is_rule_option_put_before(rule, "sid", ("content", "pcre")) is True:
            issues.append(
                {
                    "code": "S206",
                    "message": """The rule body contains the sid option before the detection logic.
Consider reording to put the sid option directly after the detection logic.""",
                },
            )

        if is_rule_option_put_before(rule, "rev", ("sid",)) is True:
            issues.append(
                {
                    "code": "S207",
                    "message": """The rule body contains the rev option before the sid option.
Consider reording to put the rev option directly after the sid option.""",
                },
            )

        if is_rule_option_last(rule, "metadata") is False:
            issues.append(
                {
                    "code": "S208",
                    "message": """The rule body contains does not have the metadata option as the last option.
Consider making metadata the last option.""",
                },
            )

        if (
            REGEX_S210.match(
                body,
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S210",
                    "message": """The rule body contains a content matched modified by depth or offset \
that is not the first content match.
Consider moving the modified content match to the beginning of the detection options.""",
                },
            )

        if count_rule_options(rule, "depth") > 1:
            issues.append(
                {
                    "code": "S211",
                    "message": """The rule body contains more than one content matche modified by depth.
Consider making the second content match relative to the first using the within option.""",
                },
            )

        if count_rule_options(rule, "offset") > 1:
            issues.append(
                {
                    "code": "S212",
                    "message": """The rule body contains more than one content matche modified by offset.
Consider making the second content match relative to the first using the distance option.""",
                },
            )

        if (
            is_rule_option_set(rule, "flow")
            and get_rule_option_position(rule, "flow") != 1
        ):
            issues.append(
                {
                    "code": "S220",
                    "message": """The rule flow option is set but not directly following the msg option.
Consider moving the flow option to directly after the msg option.""",
                },
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
                {
                    "code": "S221",
                    "message": """The rule contains flow or stream keywords before the flow option in the rule body.
Consider moving the flow option to before the flow and/or stream keywords.""",
                },
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
                {
                    "code": "S222",
                    "message": """The rule contains flow or stream keywords after content buffers or detection logic.
Consider moving the flow and/or stream keywords to before content buffers and detection options.""",
                },
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
                {
                    "code": "S223",
                    "message": """The rule contains the urilen option before the flow or stream keywords in the rule body.
Consider moving the urilen option to after the flow and/or stream keywords.""",
                },
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
                {
                    "code": "S224",
                    "message": """The rule contains the urilen option after content buffers or detection logic.
Consider moving the urilen option to before content buffers and detection options.""",
                },
            )

        # Detects pointer movement before any content or buffer option or between a buffer and a content option.
        if (
            REGEX_S230.match(
                get_rule_body(rule),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S230",
                    "message": """The rule contains pointer movement before the content option.
Consider moving the pointer movement options to after the content option.""",
                },
            )

        # Detects fast_pattern before any content or buffer option or between a buffer and a content option.
        if (
            REGEX_S231.match(
                get_rule_body(rule),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S231",
                    "message": """The rule contains the fast_pattern option before \
size options, transformation options, the content option or pointer movement options.
Consider moving the fast_pattern option to after \
size options, transformation options, the content option or pointer movement options.""",
                },
            )

        # Detects no_case before any content or buffer option or between a buffer and a content option.
        if (
            REGEX_S232.match(
                get_rule_body(rule),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S232",
                    "message": """The rule contains the nocase option before \
size options, transformation options, the content option, pointer movement options, or fast_pattern option.
Consider moving the nocase option to after \
size options, transformation options, the content option, pointer movement options, or fast_pattern option.""",
                },
            )

        # Detects modifier options before any content or buffer option or between a buffer and a content option.
        if (
            REGEX_S233.match(
                get_rule_body(rule),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S233",
                    "message": """The rule contains modifier options before the content option.
Consider moving the modifier options to after the content option.""",
                },
            )

        # Detects other detection options before any content or buffer option or between a buffer and a content option.
        if (
            REGEX_S234.match(
                get_rule_body(rule),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S234",
                    "message": """The rule contains other detection options before \
size options, transformation options, the content option, pointer movement options, nocase option, or fast_pattern option.
Consider moving the other detection options to after \
size options, transformation options,  the content option, pointer movement options, nocase option, or fast_pattern option.""",
                },
            )

        # Detects size options after any transformation options, content option or other detection options.
        if (
            REGEX_S235.match(
                get_rule_body(rule),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S235",
                    "message": """The rule contains other size options after \
any transformation options, content option or other detection options.
Consider moving the size options to after any transformation options, content option or other detection options""",
                },
            )

        # Detects transformation options after any content option or other detection options.
        if (
            REGEX_S236.match(
                get_rule_body(rule),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S236",
                    "message": """The rule contains other transformation options after \
any content option or other detection options.
Consider moving the transformation options to after any content option or other detection options""",
                },
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
                {
                    "code": "S240",
                    "message": """The rule contains the threshold option before some detection option.
Consider moving the threshold option to after the detection options.""",
                },
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
                {
                    "code": "S241",
                    "message": """The rule contains the threshold option after the reference and/or sid option.
Consider moving the threshold option to before the reference and sid options.""",
                },
            )

        return self._add_checker_metadata(issues)
