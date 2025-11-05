import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
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
    # S403, bad
    """alert ip any any -> any any (\
msg:"ET SCAN Possible Bruteforce 2022-22-04"; \
sid:2400000;)""": {
        "should_raise": ["S403"],
        "should_not_raise": [],
    },
    # S403, bad
    """alert ip any any -> any any (\
msg:"ET SCAN Possible Bruteforce 2022/04/22"; \
sid:2400000;)""": {
        "should_raise": ["S403"],
        "should_not_raise": [],
    },
    # S403, good
    """alert ip any any -> any any (\
msg:"ET SCAN Bruteforce 2022-04-22"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S403"],
    },
    # S404, bad
    """alert ip any any -> any any (\
msg:"ET MALWARE Command & Control"; \
sid:2400000;)""": {
        "should_raise": ["S404"],
        "should_not_raise": [],
    },
    # S404, good
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S404"],
    },
    # S405, bad
    """alert ip any any -> any any (\
msg:"ET MALWARE BadBot"; \
sid:2400000;)""": {
        "should_raise": ["S405"],
        "should_not_raise": [],
    },
    # S405, good
    """alert ip any any -> any any (\
msg:"ET MALWARE Win/BadBot Go"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S405"],
    },
    # S406, bad
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo.bar)"; \
sid:2400000;)""": {
        "should_raise": ["S406"],
        "should_not_raise": [],
    },
    # S406, good
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo .bar)"; \
sid:2400000;)""": {
        "should_raise": [],
        "should_not_raise": ["S406"],
    },
    # S407, bad
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo[.]bar)"; \
sid:2400000;)""": {
        "should_raise": ["S407"],
        "should_not_raise": [],
    },
    # S407, good
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo .bar)"; \
sid:2400001;)""": {
        "should_raise": [],
        "should_not_raise": ["S407"],
    },
    # S408, bad
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo. bar)"; \
sid:2400000;)""": {
        "should_raise": ["S408"],
        "should_not_raise": [],
    },
    # S408, good
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo .bar)"; \
sid:2400002;)""": {
        "should_raise": [],
        "should_not_raise": ["S408"],
    },
    # S409, bad
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo .bar) ®"; \
sid:2400000;)""": {
        "should_raise": ["S409"],
        "should_not_raise": [],
    },
    # S409, good
    """alert ip any any -> any any (\
msg:"ET MALWARE CnC Domain (foo .bar)"; \
sid:2400003;)""": {
        "should_raise": [],
        "should_not_raise": ["S409"],
    },
}


class TestMsg(suricata_check.tests.GenericChecker):
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
