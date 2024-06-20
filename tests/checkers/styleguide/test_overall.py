import os
import sys

import idstools.rule
import pytest

from ..checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
import suricata_check


class TestOverall(GenericChecker):
    @pytest.fixture(autouse=True)
    def _run_around_tests(self):
        self.checker = suricata_check.checkers.OverallChecker()

    def test_s000_bad(self):
        rule = idstools.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S000", True)

    def test_s000_bad2(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any <-> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S000", True)

    def test_s000_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S000", False)

    def test_s001_bad(self):
        rule = idstools.rule.parse(
            """alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; dns.query:"foo.bar";)""",
        )

        self.check_issue(rule, "S001", True)

    def test_s001_good(self):
        rule = idstools.rule.parse(
            """alert http $HOME_NET any -> any any (msg:"Test"; sid:1; dns.query:"foo.bar";)""",
        )

        self.check_issue(rule, "S001", False)

    def test_s011_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; priority:1;)""",
        )

        self.check_issue(rule, "S011", True)

    def test_s011_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S011", False)

    def test_s012_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; http_header:"foo";)""",
        )

        self.check_issue(rule, "S012", True)

    def test_s012_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; http.header:"foo";)""",
        )

        self.check_issue(rule, "S012", False)

    def test_s013_bad(self):
        rule = idstools.rule.parse(
            """alert ip $COOL_SERVERS any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S013", True)

    def test_s013_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S013", False)

    def test_s014_bad(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; classtype:foo-bar;)""",
        )

        self.check_issue(rule, "S014", True)

    def test_s014_good(self):
        rule = idstools.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; classtype:attempted-recon;)""",
        )

        self.check_issue(rule, "S014", False)

    def test_s020_bad(self):
        # Example modified from https://docs.suricata.io/en/latest/rules/payload-keywords.html#byte-test
        rule = idstools.rule.parse(
            """\
alert tcp any any -> any any (\
msg:"Byte_Test Example - Num = Value"; \
byte_test:2,=,0x01,0;\
)\
""",
        )

        self.check_issue(rule, "S020", True)

    def test_s020_good(self):
        # Example taken from https://docs.suricata.io/en/latest/rules/payload-keywords.html#byte-test
        rule = idstools.rule.parse(
            """\
alert tcp any any -> any any (\
msg:"Byte_Test Example - Num = Value"; \
content:"|00 01 00 02|"; byte_test:2,=,0x01,0;\
)\
""",
        )

        self.check_issue(rule, "S020", False)

    def test_s021_bad(self):
        rule = idstools.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; sid:1; \
content:"long generic"; content:"short unique";)""",
        )

        self.check_issue(rule, "S021", True)

    def test_s021_good(self):
        rule = idstools.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; sid:1; \
content:"long generic"; content:"short unique"; fast_pattern;)""",
        )

        self.check_issue(rule, "S021", False)

    def test_s030_bad(self):
        rule = idstools.rule.parse(
            """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; app-layer-protocol:http;)""",
        )

        self.check_issue(rule, "S030", True)

    def test_s030_good(self):
        rule = idstools.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
        )

        self.check_issue(rule, "S030", False)

    def test_s031_bad(self):
        rule = idstools.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|A0 BB|";)""",
        )

        self.check_issue(rule, "S031", True)

    def test_s031_good(self):
        rule = idstools.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|a0 bb|";)""",
        )

        self.check_issue(rule, "S031", False)

    def test_s031_good2(self):
        rule = idstools.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; content:"|00 11 22|";)""",
        )

        self.check_issue(rule, "S031", False)


def __main__():
    pytest.main()
