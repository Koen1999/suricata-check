import logging
import os
import sys

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check


class TestMandatory(suricata_check.tests.GenericChecker):
    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)
        self.checker = suricata_check.checkers.MandatoryChecker()

    def test_m000_bad(self):
        rule = idstools.rule.parse("""alert ip any any -> any any (sid:1;)""")

        self._test_issue(rule, "M000", True)

    def test_m000_good(self):
        rule = idstools.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:1;)""",
        )

        self._test_issue(rule, "M000", False)

    def test_m001_bad(self):
        rule = idstools.rule.parse("""alert ip any any -> any any (msg:"Test";)""")

        self._test_issue(rule, "M001", True)

    def test_m001_good(self):
        rule = idstools.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:1;)""",
        )

        self._test_issue(rule, "M001", False)


def __main__():
    pytest.main()
