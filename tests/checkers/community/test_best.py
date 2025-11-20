import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.community.BestChecker

RULES = {
    # C100, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400000;)""": {
        "should_raise": ["C100"],
        "should_not_raise": [],
    },
    # C100, good
    """alert ip any any -> any any (\
msg:"rule"; \
target: dest_ip; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["C100"],
    },
    # C101, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400001;)""": {
        "should_raise": ["C101"],
        "should_not_raise": [],
    },
    # C101, good
    """alert ip any any -> any any (\
msg:"rule"; \
metadata: created_at 2024_09_16; \
sid:2400001;)""": {
        "should_raise": [],
        "should_not_raise": ["C101"],
    },
    # C102, bad
    """alert ip any any -> any any (\
msg:"rule"; \
metadata: created_at 2024_09_16; \
sid:2400001; rev:2;)""": {
        "should_raise": ["C102"],
        "should_not_raise": [],
    },
    # C102, good
    """alert ip any any -> any any (\
msg:"rule"; \
metadata: created_at 2024_09_16, updated_at 2024_09_17; \
sid:2400001; rev:2;)""": {
        "should_raise": [],
        "should_not_raise": ["C102"],
    },
}


class TestBest(suricata_check.tests.GenericChecker):
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
