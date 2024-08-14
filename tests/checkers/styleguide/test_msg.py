import logging
import os
import sys

import idstools.rule
import pytest

from ..checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.MsgChecker

RULES = {
    # S400, bad
    """alert ip any any -> any any (\
msg:"ET rule"; \
sid:2400000;)""": {
        "should_raise": ["S400"],
        "should_not_raise": [],
    },
    # S400, good
    """alert ip any any -> any any (\
msg:"ET MALWARE rule"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S400"],
    },
    # S400, good
    """alert ip any any -> any any (\
msg:"ET MALWARE rule description"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S400"],
    },
    # S401, bad
    """alert ip any any -> any any (\
msg:"ET MALWARE test"; \
sid:2400000;)""": {
        "should_raise": ["S401"],
        "should_not_raise": [],
    },
    # S401, good
    """alert ip any any -> any any (\
msg:"ET MALWARE ELF/Mirai test"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S401"],
    },
    # S402, bad
    """alert ip any any -> any any (\
msg:"ET SCAN Possible Bruteforce"; \
sid:2400000;)""": {
        "should_raise": ["S402"],
        "should_not_raise": [],
    },
    # S402, good
    """alert ip any any -> any any (\
msg:"ET SCAN Bruteforce"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S402"],
    },
}


class TestMsg(GenericChecker):
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
