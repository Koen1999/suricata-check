"""`PrincipleChecker`."""

import logging
from typing import Optional

import idstools.rule

from suricata_check.checkers.interface.checker import CheckerInterface
from suricata_check.checkers.principle._utils import get_message
from suricata_check.utils.checker import (
    count_rule_options,
    get_rule_option,
    get_rule_options,
    is_rule_option_equal_to,
    is_rule_option_equal_to_regex,
    is_rule_option_set,
    is_rule_suboption_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import (
    ALL_DETECTION_KEYWORDS,
    BUFFER_KEYWORDS,
    CONTENT_KEYWORDS,
    IP_ADDRESS_REGEX,
    OTHER_PAYLOAD_KEYWORDS,
    SIZE_KEYWORDS,
    get_options_regex,
    get_regex_provider,
    get_rule_body,
)

_regex_provider = get_regex_provider()

_BITS_ISSET_REGEX = _regex_provider.compile(r"^\s*isset\s*,.*$")
_BITS_ISNOTSET_REGEX = _regex_provider.compile(r"^\s*isnotset\s*,.*$")
_FLOWINT_ISSET_REGEX = _regex_provider.compile(r"^.*,\s*isset\s*,.*$")
_FLOWINT_ISNOTSET_REGEX = _regex_provider.compile(r"^.*,\s*isnotset\s*,.*$")
_THRESHOLD_LIMITED_REGEX = _regex_provider.compile(r"^.*type\s+(limit|both).*$")
_FLOWBITS_ISNOTSET_REGEX = _regex_provider.compile(r"^\s*isnotset.*$")
_HTTP_URI_QUERY_PARAMETER_REGEX = _regex_provider.compile(
    rf"^\(.*\s+http\.uri\s*;\s*content\s*:\s*\"[^\"]*\?([^\"]|\\\")+\"\s*;((?!.*{get_options_regex(CONTENT_KEYWORDS).pattern}).*)|((?!.*{get_options_regex(CONTENT_KEYWORDS).pattern}).*\s+{get_options_regex(BUFFER_KEYWORDS).pattern}\s*;.*)\)$"
)
_PROXY_MSG_REGEX = _regex_provider.compile(
    r"^.*(Suspicious).*$", flags=_regex_provider.IGNORECASE
)
_SPECIFIC_MSG_REGEX = _regex_provider.compile(
    r"^.*(CVE|Vulnerability).*$", flags=_regex_provider.IGNORECASE
)


class PrincipleChecker(CheckerInterface):
    """The `PrincipleChecker` contains several checks based on the Ruling the Unruly paper and target specificity and coverage.

    Codes P000-P009 report on non-adherence to rule design principles.

    Specifically, the `PrincipleChecker` checks for the following:
        P000: No Limited Proxy, the rule does not detect a characteristic that relates directly to a malicious action,
        making it potentially noisy.

        P001: No Successful Malicious Action, the rule does not distinguish between successful and unsuccessful malicious
        actions, making it potentially noisy.

        P002: No Alert Throttling, the rule does not utilize the threshold limit option` to prevent alert flooding,
        making it potentially noisy.

        P003: No Exceptions, the rule does not include any exceptions for commom benign traffic,
        making it potentially noisy.

        P004: No Generalized Characteristic, the rule does detect a characteristic that is so specific
        that it is unlikely generalize.

        P005: No Generalized Position, the rule does detect the characteristic in a fixed position
        that and is unlikely to generalize as a result.
    """

    codes = {
        "P000": {"severity": logging.INFO},
        "P001": {"severity": logging.INFO},
        "P002": {"severity": logging.INFO},
        "P003": {"severity": logging.INFO},
        "P004": {"severity": logging.INFO},
        "P005": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "PrincipleChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if count_rule_options(
            rule, ALL_DETECTION_KEYWORDS
        ) == 0 or is_rule_option_equal_to_regex(rule, "msg", _PROXY_MSG_REGEX):
            issues.append(
                Issue(
                    code="P000",
                    message=get_message("P000"),
                ),
            )

        if (
            self.__is_rule_initiated_internally(rule) is False
            and self.__does_rule_account_for_server_response(rule) is False
            and self.__does_rule_account_for_internal_content(rule) is False
            and self.__is_rule_stateful(rule) is False
        ):
            issues.append(
                Issue(
                    code="P001",
                    message=get_message("P001"),
                ),
            )

        if not self.__is_rule_threshold_limited(rule):
            issues.append(
                Issue(
                    code="P002",
                    message=get_message("P002"),
                ),
            )

        if not self.__does_rule_have_exceptions(rule):
            issues.append(
                Issue(
                    code="P003",
                    message=get_message("P003"),
                ),
            )

        if (
            count_rule_options(rule, "content") == 0
            and not count_rule_options(
                rule,
                set(SIZE_KEYWORDS)
                .union(CONTENT_KEYWORDS)
                .union(OTHER_PAYLOAD_KEYWORDS),
            )
            > 1
        ) or (
            is_rule_option_equal_to_regex(rule, "msg", _SPECIFIC_MSG_REGEX)
            and not is_rule_option_set(rule, "pcre")
        ):
            issues.append(
                Issue(
                    code="P004",
                    message=get_message("P004"),
                ),
            )

        if self.__has_fixed_http_uri_query_parameter_location(
            rule
        ) or self.__has_single_match_at_fixed_location(rule):
            issues.append(
                Issue(
                    code="P005",
                    message=get_message("P005"),
                ),
            )

        return issues

    @staticmethod
    def __is_rule_initiated_internally(
        rule: idstools.rule.Rule,
    ) -> Optional[bool]:
        if get_rule_option(rule, "proto") in ("ip",):
            return None

        dest_addr = get_rule_option(rule, "dest_addr")
        assert dest_addr is not None
        if (
            dest_addr not in ("any", "$EXTERNAL_NET")
            and IP_ADDRESS_REGEX.match(dest_addr) is None
        ):
            if is_rule_suboption_set(
                rule, "flow", "from_server"
            ) or is_rule_suboption_set(rule, "flow", "to_client"):
                return True

        source_addr = get_rule_option(rule, "source_addr")
        assert source_addr is not None
        if (
            source_addr not in ("any", "$EXTERNAL_NET")
            and IP_ADDRESS_REGEX.match(source_addr) is None
        ):
            if is_rule_suboption_set(
                rule, "flow", "to_server"
            ) or is_rule_suboption_set(rule, "flow", "from_client"):
                return True
            if is_rule_option_set(rule, "dns.query") or is_rule_option_set(
                rule,
                "dns_query",
            ):
                return True

        return False

    @staticmethod
    def __does_rule_account_for_server_response(
        rule: idstools.rule.Rule,
    ) -> Optional[bool]:
        if get_rule_option(rule, "proto") in ("ip",):
            return None

        if is_rule_suboption_set(rule, "flow", "from_server") or is_rule_suboption_set(
            rule, "flow", "to_client"
        ):
            return True

        msg = get_rule_option(rule, "msg")
        assert msg is not None
        if "response" in msg.lower():
            return True

        return False

    @staticmethod
    def __does_rule_account_for_internal_content(
        rule: idstools.rule.Rule,
    ) -> bool:
        source_addr = get_rule_option(rule, "source_addr")
        assert source_addr is not None
        if (
            source_addr not in ("any", "$EXTERNAL_NET")
            and IP_ADDRESS_REGEX.match(source_addr) is None
        ):
            return True

        return False

    @staticmethod
    def __is_rule_stateful(
        rule: idstools.rule.Rule,
    ) -> Optional[bool]:
        if (
            is_rule_option_equal_to_regex(rule, "flowbits", _BITS_ISSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "flowint", _FLOWINT_ISSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "xbits", _BITS_ISSET_REGEX)
        ):
            return True

        # flowbits.isnotset is used to reduce false positives as well, so it does not neccesarily indicate a stateful rule.
        if (
            is_rule_option_equal_to_regex(rule, "flowbits", _BITS_ISNOTSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "flowint", _FLOWINT_ISNOTSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "xbits", _BITS_ISNOTSET_REGEX)
        ):
            return True

        return False

    @staticmethod
    def __is_rule_threshold_limited(
        rule: idstools.rule.Rule,
    ) -> bool:
        value = get_rule_option(rule, "threshold")

        if value is None:
            return False

        if _THRESHOLD_LIMITED_REGEX.match(value) is not None:
            return True

        return False

    @staticmethod
    def __does_rule_have_exceptions(
        rule: idstools.rule.Rule,
    ) -> bool:
        positive_matches = 0
        negative_matches = 0

        for option_value in get_rule_options(rule, CONTENT_KEYWORDS):
            if option_value is None:
                continue
            if option_value.startswith("!"):
                negative_matches += 1
            else:
                positive_matches += 1

        if (
            positive_matches > 0 and negative_matches > 0
        ) or is_rule_option_equal_to_regex(
            rule,
            "flowbits",
            _FLOWBITS_ISNOTSET_REGEX,
        ):
            return True

        return False

    @staticmethod
    def __has_fixed_http_uri_query_parameter_location(
        rule: idstools.rule.Rule,
    ) -> bool:
        if count_rule_options(rule, "content") != 1:
            return False

        body = get_rule_body(rule)
        if _HTTP_URI_QUERY_PARAMETER_REGEX.match(body) is not None:
            return True

        return False

    @staticmethod
    def __has_single_match_at_fixed_location(
        rule: idstools.rule.Rule,
    ) -> bool:
        if (
            count_rule_options(rule, "content") == 2  # noqa: PLR2004
            and is_rule_option_set(rule, "http.method")
            and (
                is_rule_option_equal_to(rule, "content", "GET")
                or is_rule_option_equal_to(rule, "content", "POST")
            )
        ) and count_rule_options(rule, "content") != 1:
            return False

        contents = list(
            set(get_rule_options(rule, "content")).difference(['"GET"', '"POST"'])
        )
        if len(contents) != 1:
            return False
        content = contents[0]

        if is_rule_option_set(rule, "startswith"):
            return True

        if content is not None:
            # -2 to discard quotes
            length = len(content) - 2
        else:
            length = -1

        if (
            is_rule_option_equal_to(rule, "depth", str(length))
            or is_rule_option_equal_to(rule, "bsize", str(length))
            or (
                is_rule_option_set(rule, "http.uri")
                and is_rule_option_equal_to(rule, "urilen", str(length))
            )
        ):
            return True

        return False
