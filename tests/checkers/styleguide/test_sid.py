import os
import sys

import idstools.rule
import pytest

from ..checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.SidChecker

# These rules where mentioned in the Ruling the Unruly paper.
# They originate from ET OPEN (https://rules.emergingthreats.net/OPEN_download_instructions.html)
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
msg:"ETPRO Test rule"; \
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


class TestSid(GenericChecker):
    @pytest.fixture(autouse=True)
    def _run_around_tests(self):
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
    def test_rule_bad_new(self, code, expected, raw_rule):
        if code not in RULES[raw_rule]["should_raise"]:
            # Silently skip and succeed the test
            return

        rule = idstools.rule.parse(raw_rule)

        # fail is false, so we do permit False Negatives
        self.check_issue(rule, code, expected, fail=False)

    @pytest.mark.parametrize(
        ("code", "expected", "raw_rule"),
        [
            (code, False, raw_rule)
            for code in CHECKER_CLASS.codes
            for raw_rule, expected in RULES.items()
            if code in expected["should_not_raise"]
        ],
    )
    def test_rule_good_new(self, code, expected, raw_rule):
        rule = idstools.rule.parse(raw_rule)

        # fail is true, so we do not permit False Positives
        self.check_issue(rule, code, expected, fail=True)


def __main__():
    pytest.main()
