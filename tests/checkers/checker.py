import os
import re
import sys
from typing import Mapping, Sequence

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

REGEX_PROVIDER = suricata_check.utils.get_regex_provider()


class GenericChecker:
    checker: suricata_check.checkers.interface.CheckerInterface

    def check_issue(self, rule: idstools.rule.Rule, code: str, raised: bool):
        issues = self.checker.check_rule(rule)
        codes = {issue["code"] for issue in issues}

        if raised:
            assert code in codes
        elif not raised:
            assert code not in codes

    def test_no_undeclared_codes(self):
        """Asserts the checker emits no undeclared codes."""
        output = suricata_check.process_rules_file(
            "tests/data/test.rules",
            False,
            checkers=[self.checker],
        )

        codes = set()
        for rule in output:
            issues: Sequence[Mapping] = rule["issues"]  # type: ignore reportAssignmentType
            for issue in issues:
                codes.add(issue["code"])

        for code in codes:
            if code not in self.checker.codes:
                pytest.fail(code)

    def test_code_structure(self):
        """Asserts the checker only emits codes following the allowed structure."""
        regex = REGEX_PROVIDER.compile(r"[A-Z]{1,}[0-9]{3}")
        for code in self.checker.codes:
            if regex.match(code) is None:
                pytest.fail(code)

    def test_issue_metadata(self):
        """Asserts the checker adds required metadata to emitted issues."""
        output = suricata_check.process_rules_file(
            "tests/data/test.rules",
            False,
            checkers=[self.checker],
        )

        for rule in output:
            issues: list[Mapping] = rule["issues"]  # type: ignore reportAssignmentType
            for issue in issues:
                if "checker" not in issue:
                    pytest.fail(str(issue))
