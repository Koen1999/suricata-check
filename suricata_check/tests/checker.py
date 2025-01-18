"""`GenericChecker`."""

import logging
import warnings
from functools import lru_cache
from typing import Optional

import idstools.rule
import pytest

from suricata_check.checkers.interface.checker import CheckerInterface
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import get_regex_provider

_regex_provider = get_regex_provider()

_CODE_STRUCTURE_REGEX = _regex_provider.compile(r"[A-Z]{1,}[0-9]{3}")


class GenericChecker:
    """The GenericChecker class can be extended by tests to test classes implementing `CheckerInterface`."""

    checker: CheckerInterface

    @pytest.fixture(autouse=True)
    def __run_around_tests(self: "GenericChecker") -> None:
        logging.basicConfig(level=logging.DEBUG)

    def _set_log_level(self: "GenericChecker", level: int) -> None:
        logger = logging.getLogger()
        logger.setLevel(level)
        for handler in logger.handlers:
            handler.setLevel(level)

    @lru_cache(maxsize=1)
    def _check_rule(
        self: "GenericChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        return self.checker.check_rule(rule)

    def _test_issue(
        self: "GenericChecker",
        rule: Optional[idstools.rule.Rule],
        code: str,
        raised: bool,
        fail: bool = True,
    ) -> Optional[bool]:
        """Checks whether a rule raises or does not raise an issue with a given code.

        Raises a pytest failure, warning, or returns a boolean based on the provided arguments.
        """
        if rule is None:
            pytest.fail("Rule is None")

        correct, issue = self.check_issue(rule, code, raised)

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

    def check_issue(
        self: "GenericChecker",
        rule: Optional[idstools.rule.Rule],
        code: str,
        raised: bool,
    ) -> tuple[Optional[bool], Optional[Issue]]:
        """Checks whether a rule raises an issue with a certain code and returns whether the expectation is met."""
        if rule is None:
            pytest.fail("Rule is None")

        issues: ISSUES_TYPE = self._check_rule(rule)

        self._test_no_undeclared_codes(issues)
        self._test_issue_metadata(issues)

        correct: Optional[bool] = None
        issue: Optional[Issue] = None

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

        return correct, issue if not correct else None

    def _test_no_undeclared_codes(self: "GenericChecker", issues: ISSUES_TYPE) -> None:
        """Asserts the checker emits no undeclared codes."""
        assert self.checker is not None

        codes = set()
        for issue in issues:
            codes.add(issue.code)

        for code in codes:
            if code not in self.checker.codes:
                pytest.fail(code)

    @pytest.hookimpl(trylast=True)
    def test_code_structure(self: "GenericChecker") -> None:
        """Asserts the checker only emits codes following the allowed structure."""
        for code in self.checker.codes:
            if _CODE_STRUCTURE_REGEX.match(code) is None:
                pytest.fail(code)

    def _test_issue_metadata(self: "GenericChecker", issues: ISSUES_TYPE) -> None:
        """Asserts the checker adds required metadata to emitted issues."""
        for issue in issues:
            if not hasattr(issue, "checker"):
                pytest.fail(
                    "Issue with code {} did not specify checker.".format(
                        str(issue.code)
                    )
                )
            if not hasattr(issue, "severity"):
                pytest.fail(
                    "Issue with code {} did not specify severity.".format(
                        str(issue.code)
                    )
                )
            if issue.message.strip() != issue.message:
                pytest.fail(
                    'Issue with code {} starts with or ends with whitespace in message: """{}"""'.format(
                        str(issue.code), str(issue.message)
                    )
                )
