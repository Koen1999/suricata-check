import logging
import os
import sys

import idstools.rule
import pytest

from ..checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.ReferenceChecker

RULES = {
    # S700, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400000; \
reference:CVE,2017-21354;)""": {
        "should_raise": ["S700"],
        "should_not_raise": [],
    },
    # S700, good
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400000; \
reference:cve,2017-21354;)""": {
        "should_raise": [],
        "should_not_raise": ["S700"],
    },
    # S701, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400000; \
reference:url,https://github.com/Koen1999/suricata-check;)""": {
        "should_raise": ["S701"],
        "should_not_raise": [],
    },
    # S701, good
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400000; \
reference:url,github.com/Koen1999/suricata-check;)""": {
        "should_raise": [],
        "should_not_raise": ["S701"],
    },
}


class TestReference(GenericChecker):
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

        rule = idstools.rule.parse(raw_rule)

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
        rule = idstools.rule.parse(raw_rule)

        self._test_issue(rule, code, expected)


def __main__():
    pytest.main()
