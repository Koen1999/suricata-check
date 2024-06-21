"""The `suricata_check.utils` module contains several utilities for the suricata-check main program and the checkers."""

from suricata_check.utils._path import find_rules_file
from suricata_check.utils.checker import (
    are_rule_options_always_put_before,
    are_rule_options_equal_to_regex,
    are_rule_options_put_before,
    check_rule_option_recognition,
    count_rule_options,
    get_all_variable_groups,
    get_flow_options,
    get_rule_detection_keyword_sequences,
    get_rule_option,
    get_rule_option_position,
    get_rule_option_positions,
    get_rule_options,
    get_rule_options_positions,
    get_rule_sticky_buffer_naming,
    is_rule_option_always_put_before,
    is_rule_option_equal_to,
    is_rule_option_equal_to_regex,
    is_rule_option_first,
    is_rule_option_last,
    is_rule_option_one_of,
    is_rule_option_put_before,
    is_rule_option_set,
    select_rule_options_by_regex,
)

from .regex import (
    ACTION_REGEX,
    ADDR_REGEX,
    ALL_DETECTION_KEYWORDS,
    ALL_MODIFIER_KEYWORDS,
    ALL_TRANSFORMATION_KEYWORDS,
    ALL_VARIABLES,
    BODY_REGEX,
    BUFFER_KEYWORDS,
    CLASSTYPES,
    CONTENT_KEYWORDS,
    DIRECTION_REGEX,
    FLOW_STREAM_KEYWORDS,
    HEADER_REGEX,
    IP_ADDRESS_REGEX,
    MATCH_LOCATION_KEYWORDS,
    OPTION_REGEX,
    OTHER_PAYLOAD_KEYWORDS,
    POINTER_MOVEMENT_KEYWORDS,
    PORT_REGEX,
    PROTOCOL_REGEX,
    RULE_REGEX,
    SIZE_KEYWORDS,
    get_options_regex,
    get_regex_provider,
    get_rule_body,
)
from .typing import (
    EXTENSIVE_SUMMARY_TYPE,
    ISSUES_TYPE,
    RULE_REPORTS_TYPE,
    RULE_SUMMARY_TYPE,
    SIMPLE_SUMMARY_TYPE,
    Issue,
    OutputReport,
    OutputSummary,
    RuleReport,
)
