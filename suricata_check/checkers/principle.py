# noqa: D100
from typing import Optional

import idstools.rule

from suricata_check.utils.checker import (
    count_rule_options,
    get_flow_options,
    get_rule_option,
    get_rule_options,
    is_rule_option_equal_to_regex,
    is_rule_option_set,
)
from suricata_check.utils.regex import (
    ALL_DETECTION_KEYWORDS,
    CONTENT_KEYWORDS,
    IP_ADDRESS_REGEX,
    OTHER_PAYLOAD_KEYWORDS,
    SIZE_KEYWORDS,
    get_regex_provider,
    get_rule_body,
)
from suricata_check.utils.typing import ISSUES_TYPE, Issue

from .interface import CheckerInterface

regex_provider = get_regex_provider()

BITS_ISSET_REGEX = regex_provider.compile(r"^\s*isset\s*,.*$")
BITS_ISNOTSET_REGEX = regex_provider.compile(r"^\s*isnotset\s*,.*$")
FLOWINT_ISSET_REGEX = regex_provider.compile(r"^.*,\s*isset\s*,.*$")
FLOWINT_ISNOTSET_REGEX = regex_provider.compile(r"^.*,\s*isnotset\s*,.*$")
THRESHOLD_LIMITED_REGEX = regex_provider.compile(r"^.*type\s+(limit|both).*$")
FLOWBITS_ISNOTSET_REGEX = regex_provider.compile(r"^\s*isnotset.*$")
HTTP_URI_QUERY_PARAMETER_REGEX = regex_provider.compile(
    r"^\(.*http\.uri\s*;\s*content\s*:\s*\"[^\"]*\?[^\"]+\"\s*;.*\)$",
)


class PrincipleChecker(CheckerInterface):
    """The `PrincipleChecker` contains several checks based on the Ruling the Unruly paper and target specificity and coverage.

    Codes P000-P009 report on non-adherence to rule design principles.

    Specifically, the `MandatoryChecker` checks for the following:
    - P000: No Limited Proxy, the rule does not detect a characteristic that relates directly to a malicious action
        , making it potentially noisy.
    - P001: No Successful Malicious Action, the rule does not distinguish between successful and unsuccessful malicious actions
        , making it potentially noisy.
    - P002: No Alert Throttling, the rule does not utilize the threshold limit option` to prevent alert flooding
        , making it potentially noisy.
    - P003: No Exceptions, the rule does not include any exceptions for commom benign traffic,
        making it potentially noisy.
    - P004: No Generalized Characteristic, the rule does detect a characteristic that is so specific
        that it is unlikely generalize.
    - P005: No Generalized Position, the rule does detect the characteristic in a fixed position
        that and is unlikely to generalize as a result.
    """

    codes = (
        "P000",
        "P001",
        "P002",
        "P003",
        "P004",
        "P005",
    )

    def _check_rule(
        self: "PrincipleChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if count_rule_options(rule, ALL_DETECTION_KEYWORDS) == 0:
            issues.append(
                Issue(
                    code="P000",
                    message="""No Limited Proxy, \
the rule does not detect a characteristic that relates directly to a malicious action, making it potentially noisy.""",
                ),
            )

        if (
            self._is_rule_initiated_internally(rule) is False
            and self._does_rule_account_for_server_response(rule) is False
            and self._does_rule_account_for_internal_content(rule) is False
            and self._is_rule_stateful(rule) is False
        ):
            issues.append(
                Issue(
                    code="P001",
                    message="""No Successful Malicious Action, \
the rule does not distinguish between successful and unsuccessful malicious actions, making it potentially noisy.""",
                ),
            )

        if not self._is_rule_threshold_limited(rule):
            issues.append(
                Issue(
                    code="P002",
                    message="""No Alert Throttling, \
the rule does not utilize the threshold limit option` to prevent alert flooding, making it potentially noisy.\n
Consider setting a threshold limit to prevent alert flooding.\n
Using track by_both is considered to be safe if unsure which to use.""",
                ),
            )

        if not self._does_rule_have_exceptions(rule):
            issues.append(
                Issue(
                    code="P003",
                    message="""No Exceptions, \
the rule does not include any exceptions for commom benign traffic, making it potentially noisy.\n
Consider identifying common benign traffic on which the rule may trigger and add exceptions to the rule.""",
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
        ):
            issues.append(
                Issue(
                    code="P004",
                    message="""No Generalized Characteristic, \
the rule does detect a characteristic that is so specific that it is unlikely generalize.""",
                ),
            )

        if self._has_fixed_http_uri_query_parameter_location(rule):
            issues.append(
                Issue(
                    code="P005",
                    message="""No Generalized Position, \
the rule does detect the characteristic in a fixed position that and is unlikely to generalize as a result.""",
                ),
            )

        return issues

    @staticmethod
    def _is_rule_initiated_internally(
        rule: idstools.rule.Rule,
    ) -> Optional[bool]:
        if get_rule_option(rule, "proto") in ("ip",):
            return None

        flow_options = get_flow_options(rule)

        dest_addr = get_rule_option(rule, "dest_addr")
        assert dest_addr is not None
        if (
            dest_addr not in ("any", "$EXTERNAL_NET")
            and IP_ADDRESS_REGEX.match(dest_addr) is None
        ):
            if "from_server" in flow_options or "to_client" in flow_options:
                return True

        source_addr = get_rule_option(rule, "source_addr")
        assert source_addr is not None
        if (
            source_addr not in ("any", "$EXTERNAL_NET")
            and IP_ADDRESS_REGEX.match(source_addr) is None
        ):
            if "to_server" in flow_options or "from_client" in flow_options:
                return True
            if is_rule_option_set(rule, "dns.query") or is_rule_option_set(
                rule,
                "dns_query",
            ):
                return True

        return False

    @staticmethod
    def _does_rule_account_for_server_response(
        rule: idstools.rule.Rule,
    ) -> Optional[bool]:
        if get_rule_option(rule, "proto") in ("ip",):
            return None

        flow_options = get_flow_options(rule)

        if "from_server" in flow_options or "to_client" in flow_options:
            return True

        msg = get_rule_option(rule, "msg")
        assert msg is not None
        if "response" in msg.lower():
            return True

        return False

    @staticmethod
    def _does_rule_account_for_internal_content(
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
    def _is_rule_stateful(
        rule: idstools.rule.Rule,
    ) -> Optional[bool]:
        if (
            is_rule_option_equal_to_regex(rule, "flowbits", BITS_ISSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "flowint", FLOWINT_ISSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "xbits", BITS_ISSET_REGEX)
        ):
            return True

        # flowbits.isnotset is used to reduce false positives as well, so it does not neccesarily indicate a stateful rule.
        if (
            is_rule_option_equal_to_regex(rule, "flowbits", BITS_ISNOTSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "flowint", FLOWINT_ISNOTSET_REGEX)
            or is_rule_option_equal_to_regex(rule, "xbits", BITS_ISNOTSET_REGEX)
        ):
            return True

        return False

    @staticmethod
    def _is_rule_threshold_limited(
        rule: idstools.rule.Rule,
    ) -> bool:
        value = get_rule_option(rule, "threshold")

        if value is None:
            return False

        if THRESHOLD_LIMITED_REGEX.match(value) is not None:
            return True

        return False

    @staticmethod
    def _does_rule_have_exceptions(
        rule: idstools.rule.Rule,
    ) -> bool:
        positive_matches = 0
        negative_matches = 0

        for option_value in get_rule_options(rule, CONTENT_KEYWORDS):
            if option_value.startswith("!"):
                negative_matches += 1
            else:
                positive_matches += 1

        if (
            positive_matches > 0 and negative_matches > 0
        ) or is_rule_option_equal_to_regex(
            rule,
            "flowbits",
            FLOWBITS_ISNOTSET_REGEX,
        ):
            return True

        return False

    @staticmethod
    def _has_fixed_http_uri_query_parameter_location(
        rule: idstools.rule.Rule,
    ) -> bool:
        body = get_rule_body(rule)
        if HTTP_URI_QUERY_PARAMETER_REGEX.match(body) is not None:
            return True

        return False
