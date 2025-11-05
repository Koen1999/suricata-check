import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.SidChecker

RULES = {
    # Is ET OPEN range but should be local
    """alert ip any any -> any any (\
msg:"LOCAL Test rule"; \
sid:2400000;)""": {
        "should_raise": ["S300"],
        "should_not_raise": ["S301", "S302", "S303"],
    },
    # Is local range but should be ET OPEN
    """alert ip any any -> any any (\
msg:"ET OPEN Test rule"; \
sid:1000000;)""": {
        "should_raise": ["S302"],
        "should_not_raise": ["S300", "S301", "S303"],
    },
    # Is ETPRO range but should be ET OPEN
    """alert ip any any -> any any (\
msg:"ET OPEN Test rule"; \
sid:2800000;)""": {
        "should_raise": ["S302"],
        "should_not_raise": ["S300", "S301", "S303"],
    },
    # Is unallocated range but should be ET OPEN
    """alert ip any any -> any any (\
msg:"ET OPEN Test rule"; \
sid:900000000;)""": {
        "should_raise": ["S303"],
        "should_not_raise": ["S300", "S301", "S302"],
    },
    # Is unallocated range but should be local
    """alert ip any any -> any any (\
msg:"LOCAL Test rule"; \
sid:900000000;)""": {
        "should_raise": ["S301"],
        "should_not_raise": ["S300", "S302", "S303"],
    },
    # Good, local
    """alert ip any any -> any any (\
msg:"LOCAL Test rule"; \
sid:1000000;)""": {
        "should_raise": [],
        "should_not_raise": ["S300", "S301", "S302", "S303"],
    },
    # Good, ET OPEN
    """alert ip any any -> any any (\
msg:"ET OPEN Test rule"; \
sid:2103999;)""": {
        "should_raise": [],
        "should_not_raise": ["S300", "S301", "S302", "S303"],
    },
}


class TestSid(suricata_check.tests.GenericChecker):
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

        # fail is true, so we do not permit False Positives
        self._test_issue(rule, code, expected)


def __main__():
    pytest.main()
