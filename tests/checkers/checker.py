import logging
import os
import sys
import warnings
from functools import lru_cache
from typing import Optional

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

_regex_provider = suricata_check.utils.regex.get_regex_provider()


class GenericChecker:
    checker: suricata_check.checkers.interface.CheckerInterface

    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)

    @lru_cache(maxsize=1)
    def _check_rule(
        self,
        rule: idstools.rule.Rule,
    ) -> suricata_check.utils.typing.ISSUES_TYPE:
        return self.checker.check_rule(rule)

    def check_issue(
        self,
        rule: Optional[idstools.rule.Rule],
        code: str,
        raised: bool,
        fail: bool = True,
    ):
        if rule is None:
            pytest.fail("Rule is None")

        issues: suricata_check.utils.typing.ISSUES_TYPE = self._check_rule(rule)
        correct: Optional[bool] = None
        issue: Optional[suricata_check.utils.typing.Issue] = None

        if raised:
            correct = False
            for issue in issues:
                if issue.code == code:
                    correct = True
                    break
            issue = None
        elif not raised:
            correct = True
            for issue in issues:
                if issue.code == code:
                    correct = False
                    break

        if correct is not True:
            msg = f"""\
{'Unexpected' if not raised else 'Missing'} code {code}.
{rule['raw']}
{issue}\
"""
            if fail:
                pytest.fail(msg)
            else:
                warnings.warn(RuntimeWarning(msg))

    def test_no_undeclared_codes(self):
        """Asserts the checker emits no undeclared codes."""
        assert self.checker is not None

        output = suricata_check.process_rules_file(
            "tests/data/test.rules",
            False,
            checkers=[self.checker],
        )

        codes = set()
        rules: suricata_check.utils.typing.RULE_REPORTS_TYPE = output.rules
        for rule in rules:
            issues: suricata_check.utils.typing.ISSUES_TYPE = rule.issues
            for issue in issues:
                codes.add(issue.code)

        for code in codes:
            if code not in self.checker.codes:
                pytest.fail(code)

    def test_code_structure(self):
        """Asserts the checker only emits codes following the allowed structure."""
        regex = _regex_provider.compile(r"[A-Z]{1,}[0-9]{3}")
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

        rules: suricata_check.utils.typing.RULE_REPORTS_TYPE = output.rules
        for rule in rules:
            issues: suricata_check.utils.typing.ISSUES_TYPE = rule.issues
            for issue in issues:
                if not hasattr(issue, "checker"):
                    pytest.fail(str(issue))
