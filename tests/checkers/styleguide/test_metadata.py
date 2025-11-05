import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.MetadataChecker

RULES = {
    # S800, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400000;)""": {
        "should_raise": ["S800"],
        "should_not_raise": [],
    },
    # S800, good
    """alert ip any any -> any any (\
msg:"rule"; \
metadata:attack_target Client_and_Server; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S800"],
    },
    # S801, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400001;)""": {
        "should_raise": ["S801"],
        "should_not_raise": [],
    },
    # S801, good
    """alert ip any any -> any any (\
msg:"rule"; \
metadata:signature_severity Major; \
sid:2400001;)""": {
        "should_raise": [],
        "should_not_raise": ["S801"],
    },
    # S802, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400002;)""": {
        "should_raise": ["S802"],
        "should_not_raise": [],
    },
    # S802, good
    """alert ip any any -> any any (\
msg:"rule"; \
metadata:performance_impact Low; \
sid:2400002;)""": {
        "should_raise": [],
        "should_not_raise": ["S802"],
    },
    # S803, bad
    """alert ip any any -> any any (\
msg:"rule"; \
sid:2400003;)""": {
        "should_raise": ["S803"],
        "should_not_raise": [],
    },
    # S803, good
    """alert ip any any -> any any (\
msg:"rule"; \
metadata:deployment Perimeter; \
sid:2400003;)""": {
        "should_raise": [],
        "should_not_raise": ["S803"],
    },
}


class TestMetadata(suricata_check.tests.GenericChecker):
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

        rule = suricata_check.rule.parse(raw_rule)

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
        rule = suricata_check.rule.parse(raw_rule)

        self._test_issue(rule, code, expected)


def __main__():
    pytest.main()
