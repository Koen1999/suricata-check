import logging
import os
import sys

import idstools.rule
import pytest

from ..checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.StateChecker

RULES = {
    # S500, bad
    """alert ip any any -> any any (\
msg:"rule"; \
flow:to_server,established; \
sid:2400000;)""": {
        "should_raise": ["S500"],
        "should_not_raise": [],
    },
    # S500, good
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S500"],
    },
    # S501, bad
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,from_client; \
sid:2400001;)""": {
        "should_raise": ["S501"],
        "should_not_raise": [],
    },
    # S501, good
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
sid:2400001;)""": {
        "should_raise": [],
        "should_not_raise": ["S501"],
    },
    # S510, bad
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
flowbits:set,log4j; \
sid:2400001;)""": {
        "should_raise": ["S510"],
        "should_not_raise": [],
    },
    # S510, good
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
flowbits:set,ET.log4j; \
sid:2400001;)""": {
        "should_raise": [],
        "should_not_raise": ["S510"],
    },
    # S511, bad
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
flowbits:set,ET.log4j; \
sid:2400002;)""": {
        "should_raise": ["S511"],
        "should_not_raise": [],
    },
    # S511, good
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
flowbits:set,ET.log4j; \
flowbits:noalert; \
sid:2400002;)""": {
        "should_raise": [],
        "should_not_raise": ["S511"],
    },
    # S520, bad
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
xbits:set,log4j, track ip_src; \
sid:2400001;)""": {
        "should_raise": ["S520"],
        "should_not_raise": [],
    },
    # S520, good
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
xbits:set,ET.log4j, track ip_src; \
sid:2400001;)""": {
        "should_raise": [],
        "should_not_raise": ["S520"],
    },
    # S521, bad
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
xbits:set,ET.log4j, track ip_src; \
sid:2400002;)""": {
        "should_raise": ["S521"],
        "should_not_raise": [],
    },
    # S521, good
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
xbits:set,ET.log4j, track ip_src; \
noalert; \
sid:2400002;)""": {
        "should_raise": [],
        "should_not_raise": ["S521"],
    },
    # S522, bad
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
xbits:set,ET.log4j, track ip_src; \
noalert; \
sid:2400003;)""": {
        "should_raise": ["S522"],
        "should_not_raise": [],
    },
    # S522, good
    """alert ip any any -> any any (\
msg:"rule"; \
flow:established,to_server; \
xbits:set,ET.log4j, track ip_src, expire 3600; \
noalert; \
sid:2400003;)""": {
        "should_raise": [],
        "should_not_raise": ["S522"],
    },
}


class TestState(GenericChecker):
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
