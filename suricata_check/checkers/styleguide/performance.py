"""`PerformanceChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    get_rule_keyword_sequences,
    is_rule_option_set,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import (
    BASE64_BUFFER_KEYWORDS,
    BASE64_TRANSFORMATION_KEYWORDS,
)


class PerformanceChecker(CheckerInterface):
    """The `PerformanceChecker` contains several checks for Suricata performance issues.

    Codes S900-910 report on usage of options that can slow the detection engine.
    """

    codes = {
        "S900": {"severity": logging.INFO},
        "S901": {"severity": logging.INFO},
        "S902": {"severity": logging.INFO},
        "S903": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "PerformanceChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if is_rule_option_set(rule, "http.response_body"):
            issues.append(
                Issue(
                    code="S900",
                    message="""\
The rule uses the `http.response_body` option, which is known to be slow in Suricata 5.
Consider specifying the `file.data` option instead.\
""",
                ),
            )

        for option in BASE64_BUFFER_KEYWORDS + BASE64_TRANSFORMATION_KEYWORDS:
            if is_rule_option_set(rule, option):
                issues.append(
                    Issue(
                        code="S901",
                        message="""\
The rule uses a `base64_` keyword, which is known to be slow.
Consider detection methods avoiding the usage of `base64_` keywords to improve runtime performance.\
""",
                    ),
                )

        for sequence in get_rule_keyword_sequences(rule):
            if "http.uri" in sequence and "bsize" in sequence:
                issues.append(
                    Issue(
                        code="S902",
                        message="""\
The rule uses the `bsize` keyword on the `http.uri` buffer, which is known to be slow.
Consider using the `urilen` option instead to improve runtime performance.\
""",
                    ),
                )

        return issues
