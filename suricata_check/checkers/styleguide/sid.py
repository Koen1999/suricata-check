"""`SidChecker`."""

import logging
from collections.abc import Mapping, Sequence
from typing import Optional

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import get_rule_option
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import get_regex_provider

SID_ALLOCATION: Mapping[str, Sequence[tuple[int, int]]] = {
    "local": [(1000000, 1999999)],
    "ET OPEN": [
        (2000000, 2103999),
        (2400000, 2609999),
    ],
    "ET": [(2700000, 2799999)],
    "ETPRO": [(2800000, 2899999)],
}

_regex_provider = get_regex_provider()

_MSG_PREFIX_REGEX = _regex_provider.compile(r"^\"([A-Z0-9 ]*).*\"$")

_logger = logging.getLogger(__name__)


class SidChecker(CheckerInterface):
    """The `SidChecker` contains several checks based on the Suricata SID allocation.

    Specifically, the `SidChecker` checks for the following:
        S300: Allocation to reserved SID range, whereas no range is reserved for the rule.

        S301: Allocation to unallocated SID range, whereas local range should be used.

        S302: Allocation to wrong reserved SID range, whereas another reserved range should be used.

        S303: Allocation to unallocated SID range, whereas a reserved range should be used.
    """

    codes = {
        "S300": {"severity": logging.INFO},
        "S301": {"severity": logging.INFO},
        "S302": {"severity": logging.INFO},
        "S303": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "SidChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        sid = get_rule_option(rule, "sid")
        msg = get_rule_option(rule, "msg")

        if sid is not None and msg is not None:
            sid = int(sid)
            range_name = self.__get_range_name(sid, SID_ALLOCATION)
            prefix = self.__get_msg_prefix(msg)

            if (
                prefix not in SID_ALLOCATION.keys()
                and range_name is not None
                and range_name != "local"
            ):
                issues.append(
                    Issue(
                        code="S300",
                        message=f"""\
Allocation to reserved SID range, whereas no range is reserved for the rule.
Consider using an sid in one of the following ranges: {SID_ALLOCATION["local"]}.\
""",
                    ),
                )

            if prefix not in SID_ALLOCATION.keys() and range_name is None:
                issues.append(
                    Issue(
                        code="S301",
                        message=f"""\
Allocation to unallocated SID range, whereas local range should be used.
Consider using an sid in one of the following ranges: {SID_ALLOCATION["local"]}.\
""",
                    ),
                )

            if prefix in SID_ALLOCATION.keys() and (
                range_name is not None
                and not (prefix + " ").startswith(range_name + " ")
                and not (range_name + " ").startswith(prefix + " ")
            ):
                issues.append(
                    Issue(
                        code="S302",
                        message=f"""\
Allocation to wrong reserved SID range, whereas another reserved range should be used.
Consider using an sid in one of the following ranges: {SID_ALLOCATION[prefix]}.\
""",
                    ),
                )

            if prefix in SID_ALLOCATION.keys() and range_name is None:
                issues.append(
                    Issue(
                        code="S303",
                        message=f"""\
Allocation to unallocated SID range, whereas a reserved range should be used.
Consider using an sid in one of the following ranges: {SID_ALLOCATION[prefix]}.\
""",
                    ),
                )

        return issues

    @staticmethod
    def __in_range(sid: int, sid_range: Sequence[tuple[int, int]]) -> bool:
        for start, end in sid_range:
            if start <= sid <= end:
                return True

        return False

    @staticmethod
    def __get_range_name(
        sid: int,
        ranges: Mapping[str, Sequence[tuple[int, int]]],
    ) -> Optional[str]:
        for range_name, sid_range in ranges.items():
            for start, end in sid_range:
                if start <= sid <= end:
                    _logger.debug("Detected sid from range: %s", range_name)
                    return range_name
        return None

    @staticmethod
    def __get_msg_prefix(msg: str) -> str:
        match = _MSG_PREFIX_REGEX.match(msg)
        assert match is not None

        parts = match.group(1).strip().split(" ")
        prefix: str = ""
        for i in list(reversed(range(len(parts)))):
            prefix = " ".join(parts[: i + 1])
            if prefix in SID_ALLOCATION.keys() or " " not in prefix:
                break

        _logger.debug("Detected prefix: %s", prefix)

        return prefix
