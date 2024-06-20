import os
import sys

import idstools.rule
import pytest

from ..checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
import suricata_check


class TestWhitespace(GenericChecker):
    @pytest.fixture(autouse=True)
    def _run_around_tests(self):
        self.checker = suricata_check.checkers.WhitespaceChecker()

    def test_s100_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any ( msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S100", True)

    def test_s100_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S100", False)

    def test_s101_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; )""",
        )

        self.check_issue(rule, "S101", True)

    def test_s101_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S101", False)

    def test_s102_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg :"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S102", True)

    def test_s102_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S102", False)

    def test_s103_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg: "Test"; sid:1;)""",
        )

        self.check_issue(rule, "S103", True)

    def test_s103_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S103", False)

    def test_s104_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test" ; sid:1;)""",
        )

        self.check_issue(rule, "S104", True)

    def test_s104_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S104", False)

    def test_s105_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test";  sid:1;)""",
        )

        self.check_issue(rule, "S105", True)

    def test_s105_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S105", False)

    def test_s106_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|00  11|";)""",
        )

        self.check_issue(rule, "S106", True)

    def test_s106_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|00 11|";)""",
        )

        self.check_issue(rule, "S106", False)

    def test_s110_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test";sid:1;)""",
        )

        self.check_issue(rule, "S110", True)

    def test_s110_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S110", False)

    def test_s111_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|0011|";)""",
        )

        self.check_issue(rule, "S111", True)

    def test_s111_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|00 11|";)""",
        )

        self.check_issue(rule, "S111", False)

    def test_s120_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:" ";)""",
        )

        self.check_issue(rule, "S120", True)

    def test_s120_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|20|";)""",
        )

        self.check_issue(rule, "S120", False)

    def test_s120_bad2(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"\\|";)""",
        )

        self.check_issue(rule, "S120", True)

    def test_s120_good2(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|7c|";)""",
        )

        self.check_issue(rule, "S120", False)

    def test_s120_good3(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|7c 8a|";)""",
        )

        self.check_issue(rule, "S120", False)

    def test_s121_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; pcre:"/ /";)""",
        )

        self.check_issue(rule, "S121", True)

    def test_s121_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; pcre:"/\\x20/";)""",
        )

        self.check_issue(rule, "S121", False)

    def test_s121_bad2(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; pcre:"/\\\\/";)""",
        )

        self.check_issue(rule, "S121", True)

    def test_s121_good2(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; pcre:"/\\x5c/";)""",
        )

        self.check_issue(rule, "S121", False)

    def test_s121_good3(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; pcre:"/^\\x5c$/";)""",
        )

        self.check_issue(rule, "S121", False)

    def test_s122_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"\\|";)""",
        )

        self.check_issue(rule, "S122", True)

    def test_s122_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|7c|";)""",
        )

        self.check_issue(rule, "S122", False)

    def test_s123_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; pcre:"\\|";)""",
        )

        self.check_issue(rule, "S123", True)

    def test_s123_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; pcre:"\\x7c";)""",
        )

        self.check_issue(rule, "S123", False)


def __main__():
    pytest.main()
