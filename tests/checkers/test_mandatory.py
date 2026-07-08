import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check


class TestMandatory(suricata_check.tests.GenericChecker):
    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)
        self.checker = suricata_check.checkers.MandatoryChecker()

    def test_m000_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip any any -> any any (sid:1;)""",
        )

        self._test_issue(rule, "M000", True)

    def test_m000_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:1;)""",
        )

        self._test_issue(rule, "M000", False)

    def test_m001_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip any any -> any any (msg:"Test";)""",
        )

        self._test_issue(rule, "M001", True)

    def test_m001_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:1;)""",
        )

        self._test_issue(rule, "M001", False)

    def test_m002_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http any any -> any any (\
msg:"KOEN CTF - Flag retrieved"; \
flow:established_to_client; \
file.data; \
content:"ECSC"; \
sid:1000001; rev:1;)""",
        )

        self._test_issue(rule, "M002", True)

    def test_m002_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http any any -> any any (\
msg:"KOEN CTF - Flag retrieved"; \
flow:established,to_client; \
file.data; \
content:"ECSC"; \
sid:1000001; rev:1;)""",
        )

        self._test_issue(rule, "M002", False)


def __main__():
    pytest.main()
