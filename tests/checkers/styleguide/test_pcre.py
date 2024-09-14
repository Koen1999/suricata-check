import logging
import os
import sys

import idstools.rule
import pytest

from ..checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.PcreChecker

RULES = {
    # S600, bad
    """alert ip any any -> any any (\
msg:"rule"; \
pcre:"/stuff[a-z]+/";\
flow:established,to_server; \
sid:2400000;)""": {
        "should_raise": ["S600"],
        "should_not_raise": [],
    },
    # S600, good
    """alert ip any any -> any any (\
msg:"rule"; \
content:"stuff"; startswith; \
pcre:"/stuff[a-z]+/";\
flow:established,to_server; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S600"],
    },
    # S601, bad
    """alert ip any any -> any any (\
msg:"rule"; \
content:"stuff"; startswith; \
pcre:"/stuff[a-z]+.*/";\
flow:established,to_server; \
sid:2400001;)""": {
        "should_raise": ["S601"],
        "should_not_raise": [],
    },
    # S601, good
    """alert ip any any -> any any (\
msg:"rule"; \
content:"stuff"; startswith; \
pcre:"/stuff[a-z]+.{20}/";\
flow:established,to_server; \
sid:2400001;)""": {
        "should_raise": [],
        "should_not_raise": ["S601"],
    },
}


class TestPcre(GenericChecker):
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
