import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.PerformanceChecker

RULES = {
    # S900, bad
    """alert ip any any -> any any (\
msg:"rule"; \
http.response_body; content:"foobar"; \
sid:2400000;)""": {
        "should_raise": ["S900"],
        "should_not_raise": [],
    },
    # S900, good
    """alert ip any any -> any any (\
msg:"rule"; \
file.data; content:"foobar"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S900"],
    },
    # S901, good
    """alert ip any any -> any any (\
msg:"rule"; \
base64_data; content:"foobar"; \
sid:2400000;)""": {
        "should_raise": ["S901"],
        "should_not_raise": [],
    },
    # S901, good
    """alert ip any any -> any any (\
msg:"rule"; \
content:"Zm9vYmFy"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S901"],
    },
    # S902, bad
    """alert ip any any -> any any (\
msg:"rule"; \
http.uri; bsize:5; \
sid:2400000;)""": {
        "should_raise": ["S902"],
        "should_not_raise": [],
    },
    # S902, good
    """alert ip any any -> any any (\
msg:"rule"; \
urilen:5; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S902"],
    },
}


class TestPerformance(suricata_check.tests.GenericChecker):
    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)
        self.checker = CHECKER_CLASS()

    @pytest.mark.parametrize(
        ("code", "expected", "raw_rule"),
        [
            (code, True, raw_rule)
            for code in CHECKER_CLASS.codes
            for raw_rule, expected in RULES.items()
            if code in expected["should_raise"]
        ],
    )
    def test_rule_bad(self, code, expected, raw_rule):
        if code not in RULES[raw_rule]["should_raise"]:
            # Silently skip and succeed the test
            return

        rule = suricata_check.utils.rule.parse(raw_rule)

        self._test_issue(rule, code, expected)

    @pytest.mark.parametrize(
        ("code", "expected", "raw_rule"),
        [
            (code, False, raw_rule)
            for code in CHECKER_CLASS.codes
            for raw_rule, expected in RULES.items()
            if code in expected["should_not_raise"]
        ],
    )
    def test_rule_good(self, code, expected, raw_rule):
        rule = suricata_check.utils.rule.parse(raw_rule)

        self._test_issue(rule, code, expected)


def __main__():
    pytest.main()
