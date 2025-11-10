import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
import suricata_check


class TestOrder(suricata_check.tests.GenericChecker):
    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)
        self.checker = suricata_check.checkers.OrderChecker()

    def test_s200_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
content:"test"; \
msg:"Test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S200", True)

    def test_s200_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S200", False)

    def test_s201_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
reference:url,foo.bar; \
content:"test"; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S201", True)

    def test_s201_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S201", False)

    def test_s202_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
classtype:bad-unknown; \
reference:url,foo.bar; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S202", True)

    def test_s202_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S202", False)

    def test_s203_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
classtype:bad-unknown; \
content:"test"; \
reference:url,foo.bar; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S203", True)

    def test_s203_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S203", False)

    def test_s204_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
sid:1; \
classtype:bad-unknown; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S204", True)

    def test_s204_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S204", False)

    def test_s205_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
sid:1; \
reference:url,foo.bar; \
classtype:bad-unknown; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S205", True)

    def test_s205_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S205", False)

    def test_s206_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
sid:1; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S206", True)

    def test_s206_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S206", False)

    def test_s207_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
rev:1; \
sid:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S207", True)

    def test_s207_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S207", False)

    def test_s208_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
metadata:performance_impact Low; \
rev:1;)""",
        )

        self._test_issue(rule, "S208", True)

    def test_s208_bad2(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
metadata:performance_impact Low; \
sid:1; \
rev:1;)""",
        )

        self._test_issue(rule, "S208", True)

    def test_s208_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
reference:url,foo.bar; \
classtype:bad-unknown; \
sid:1; \
rev:1; \
metadata:performance_impact Low;)""",
        )

        self._test_issue(rule, "S208", False)

    def test_s210_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test1"; \
content:"test2"; \
offset:0; \
sid:1;)""",
        )

        self._test_issue(rule, "S210", True)

    def test_s210_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test2"; \
offset:0; \
content:"test1"; \
sid:1;)""",
        )

        self._test_issue(rule, "S210", False)

    def test_s211_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test0"; \
depth:5; \
content:"test1"; \
depth:10; \
sid:1;)""",
        )

        self._test_issue(rule, "S211", True)

    def test_s211_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test0"; \
depth:5; \
content:"test1"; \
within:5; \
sid:1;)""",
        )

        self._test_issue(rule, "S211", False)

    def test_s212_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test0"; \
offset:0; \
content:"test1"; \
offset:5; \
sid:1;)""",
        )

        self._test_issue(rule, "S212", True)

    def test_s212_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert ip $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test0"; \
offset:0; \
content:"test1"; \
distance:0; \
sid:1;)""",
        )

        self._test_issue(rule, "S212", False)

    def test_s220_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
flow:established; \
sid:1;)""",
        )

        self._test_issue(rule, "S220", True)

    def test_s220_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
flow:established; \
content:"test"; \
sid:1;)""",
        )

        self._test_issue(rule, "S220", False)

    def test_s221_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
flow.age:3; \
flow:established; \
content:"test"; \
sid:1;)""",
        )

        self._test_issue(rule, "S221", True)

    def test_s221_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
flow:established; \
flow.age:3; \
content:"test"; \
sid:1;)""",
        )

        self._test_issue(rule, "S221", False)

    def test_s222_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
flow:established; \
content:"test"; \
flow.age:3; \
sid:1;)""",
        )

        self._test_issue(rule, "S222", True)

    def test_s222_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
flow:established; \
flow.age:3; \
content:"test"; \
sid:1;)""",
        )

        self._test_issue(rule, "S222", False)

    def test_s223_bad(self):
        # Example taken from https://docs.suricata.io/en/latest/rules/http-keywords.html#urilen
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
urilen:11; \
flow:established,to_server; \
http.method; content:"GET"; \
classtype:bad-unknown; sid:40; rev:1;)""",
        )

        self._test_issue(rule, "S223", True)

    def test_s223_good(self):
        # Example taken from https://docs.suricata.io/en/latest/rules/http-keywords.html#urilen
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
urilen:11; \
http.method; content:"GET"; \
classtype:bad-unknown; sid:40; rev:1;)""",
        )

        self._test_issue(rule, "S223", False)

    def test_s224_bad(self):
        # Example taken from https://docs.suricata.io/en/latest/rules/http-keywords.html#urilen
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.method; content:"GET"; \
urilen:11; \
classtype:bad-unknown; sid:40; rev:1;)""",
        )

        self._test_issue(rule, "S224", True)

    def test_s224_good(self):
        # Example taken from https://docs.suricata.io/en/latest/rules/http-keywords.html#urilen
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
urilen:11; \
http.method; content:"GET"; \
classtype:bad-unknown; sid:40; rev:1;)""",
        )

        self._test_issue(rule, "S224", False)

    def test_s230_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
depth:4; \
content:"Test"; \
fast_pattern; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S230", True)

    def test_s230_bad2(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
depth:4; \
content:"Test"; \
fast_pattern; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S230", True)

    def test_s230_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S230", False)

    def test_s230_good2(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
content:"Test"; \
depth:4; \
content:"Test"; \
within:4; \
fast_pattern; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S230", False)

    def test_s231_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
fast_pattern; \
content:"Test"; \
depth:4; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S231", True)

    def test_s231_bad2(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
fast_pattern; \
content:"Test"; \
depth:4; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S231", True)

    def test_s231_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S231", False)

    def test_s232_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
nocase; \
content:"Test"; \
depth:4; \
fast_pattern; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S232", True)

    def test_s232_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S232", False)

    def test_s233_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
nocase; \
content:"Test"; \
depth:4; \
fast_pattern; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S233", True)

    def test_s233_bad2(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
nocase; \
content:"Test"; \
depth:4; \
fast_pattern; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S233", True)

    def test_s233_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!1, relative; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S233", False)

    def test_s234_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
isdataat:!5; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S234", True)

    def test_s234_bad2(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
isdataat:!5; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S234", True)

    def test_s234_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!5; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S234", False)

    def test_s235_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
content:"Test"; \
bsize:5; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!5; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S235", True)

    def test_s235_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
bsize:5; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!5; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S235", False)

    def test_s236_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
bsize:5; \
content:"Test"; \
to_lowercase; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!5; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S236", True)

    def test_s236_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
http.user_agent; \
to_lowercase; \
bsize:5; \
content:"Test"; \
depth:4; \
fast_pattern; \
nocase; \
isdataat:!5; \
sid:1; rev:1;)""",
        )

        self._test_issue(rule, "S236", False)

    def test_s240_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
threshold:type both,track by_both,count 1,seconds 3600;\
content:"Test"; \
sid:1; \
rev:1;)""",
        )

        self._test_issue(rule, "S240", True)

    def test_s240_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
content:"Test"; \
threshold:type both,track by_both,count 1,seconds 3600;\
sid:1; \
rev:1;)""",
        )

        self._test_issue(rule, "S240", False)

    def test_s241_bad(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
content:"Test"; \
sid:1; \
threshold:type both,track by_both,count 1,seconds 3600;\
rev:1;)""",
        )

        self._test_issue(rule, "S241", True)

    def test_s241_good(self):
        rule = suricata_check.utils.rule.parse(
            """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"HTTP Request"; \
flow:established,to_server; \
content:"Test"; \
threshold:type both,track by_both,count 1,seconds 3600;\
sid:1; \
rev:1;)""",
        )

        self._test_issue(rule, "S241", False)


def __main__():
    pytest.main()
