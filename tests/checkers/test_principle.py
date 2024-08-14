import logging
import os
import sys

import idstools.rule
import numpy
import pandas
import pytest
import sklearn.metrics

from .checker import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.PrincipleChecker

# These rules where mentioned in the Ruling the Unruly paper.
# They originate from ET OPEN (https://rules.emergingthreats.net/OPEN_download_instructions.html)
RULES = {
    # Rule that generalized well
    """alert udp any 53 -> $HOME_NET any (\
msg:"ET MALWARE Possible Zeus GameOver/FluBot Related DGA NXDOMAIN Responses"; \
byte_test:1,&,128,2; byte_test:1,&,1,3; byte_test:1,&,2,3; \
content:"|00 01 00 00 00 01|"; offset:4; depth:6; \
pcre:"/^..[\\x0d-\\x20][a-z]{13,32}(?:\\x03(?:biz|com|net|org)|\\x04info|\\x02ru)\\x00\\x00\\x01\\x00\\x01/Rs"; \
threshold:type both, track by_dst, count 12, seconds 120;)""": {
        "should_raise": ["P003"],
        "should_not_raise": ["P000", "P001", "P002", "P004"],
    },
    # Noisy rule
    """alert http $EXTERNAL_NET any -> $HOME_NET any (\
msg:"ET SCAN OpenVAS User-Agent Inbound"; \
flow:established,to_server; \
http.user_agent; content:"OpenVAS";)""": {
        "should_raise": ["P001", "P002", "P003"],
        "should_not_raise": ["P004"],
    },
    # Noisy and too specific rule
    """alert http any any -> $HTTP_SERVERS any (\
msg:"ET WEB_SERVER ColdFusion administrator access"; \
flow:established,to_server; \
http.method; content:"GET"; nocase; \
http.uri; content:"/CFIDE/administrator"; nocase;)""": {
        "should_raise": ["P001", "P002", "P004"],
        "should_not_raise": [],
    },
    # Noisy and too specific rule
    """alert http any any -> $HTTP_SERVERS any (\
msg:"ET WEB_SERVER ColdFusion adminapi access"; \
flow:established,to_server; \
http.method; content:"GET"; nocase; \
http.uri; content:"/CFIDE/adminapi";)"; nocase;)""": {
        "should_raise": ["P001", "P002", "P004"],
        "should_not_raise": [],
    },
    # Noisy rule
    """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"ET USER_AGENTS Go HTTP Client User-Agent"; \
flow:established,to_server; \
http.user_agent; content:"Go-http-client"; nocase;)""": {
        "should_raise": ["P000", "P002", "P003"],
        "should_not_raise": ["P001", "P004"],
    },
    # Too specific rule
    """alert http any any -> $HOME_NET any (\
msg:"ET EXPLOIT D-Link DSL-2750B - OS Command Injection"; \
flow:established,to_server; \
http.uri; content:"/login.cgi?cli="; pcre:"/^[ a-zA-Z0-9+_]*[\\x27\\x3b]/Ri";)""": {
        "should_raise": ["P001", "P002", "P003", "P005"],
        "should_not_raise": ["P004"],
    },
    # Better rule
    """alert http $EXTERNAL_NET any -> $HOME_NET any (\
msg:"ET SCAN OpenVASVT RCE Test String in HTTP Request Inbound"; \
flow:established,to_server; \
content:"T3BlblZBU1ZUIFJDRSBUZXN0"; \
threshold:type limit, track by_src, count 1, seconds 60;)""": {
        "should_raise": ["P001", "P003"],
        "should_not_raise": ["P000", "P002"],
    },
    # Improved rule
    """alert http $EXTERNAL_NET any -> $HOME_NET any (\
msg:"ET SCAN OpenVAS User-Agent Inbound"; \
flow:established,to_server; \
http.user_agent; content:"OpenVAS"; \
threshold:type limit, track by_src, count 1, seconds, 60;)""": {
        "should_raise": ["P001", "P003"],
        "should_not_raise": ["P002", "P004"],
    },
    # Improved rule
    """alert http $HTTP_SERVERS any -> any any (\
msg:"ET WEB_SERVER ColdFusion successful administrator access"; \
flow:established,to_client; \
flowbits: isset, coldfusion_admin_access; \
http.stat_code; content:"200";)""": {
        "should_raise": ["P002", "P003"],
        "should_not_raise": ["P001"],
    },
    # Improved rule
    """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"ET USER_AGENTS Go HTTP Client User-Agent"; \
flow:established,to_server; \
http.user_agent; content:"Go-http-client"; nocase; \
http.request_header; content:!"X-Tailscale-Challenge|3a 20|";)""": {
        "should_raise": ["P002"],
        "should_not_raise": ["P001", "P003"],
    },
    # Improved rule
    """alert http any any -> $HTTP_SERVERS any (\
msg:"ET WEB_SERVER ColdFusion access"; \
flow:established,to_server; \
http.method; content:"GET"; nocase; \
http.uri; content:"/CFIDE/"; pcre:"/\\/CFIDE(administrator|adminapi)/i";)"; nocase;)""": {
        "should_raise": ["P001", "P002", "P003"],
        "should_not_raise": ["P004"],
    },
    # Improved rule
    """alert http any any -> $HOME_NET any (\
msg:"ET EXPLOIT D-Link DSL-2750B - OS Command Injection"; \
flow:established,to_server; \
http.uri; content:"/login.cgi?"; content:"cli="; pcre:"/^[ a-zA-Z0-9+_]*[\\x27\\x3b]/Ri";)""": {
        "should_raise": ["P001", "P002", "P003"],
        "should_not_raise": ["P004", "P005"],
    },
    # Example of rule with a lot of exceptions
    """alert http $HOME_NET any -> $EXTERNAL_NET any (\
msg:"ET MALWARE Terse alphanumeric executable downloader high likelihood of being hostile";\
flow:established,to_server;\
http.uri; content:"/"; content:".exe"; distance:1; within:8; endswith; pcre:"/\\/[A-Z]?[a-z]{1,3}[0-9]?\\.exe$/";\
http.header; content:!"koggames"; \
http.host; content:!"download.bitdefender.com"; endswith; \
content:!".appspot.com"; endswith; \
content:!"kaspersky.com"; endswith; \
content:!".sophosxl.net"; endswith;\
http.header_names; content:!"Referer"; nocase;)""": {
        "should_raise": ["P002"],
        "should_not_raise": ["P001", "P003", "P004", "P005"],
    },
}

_logger = logging.getLogger(__name__)


class TestPrinciple(GenericChecker):
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

        # fail is false, so we do permit False Negatives
        self._test_issue(rule, code, expected, fail=False)

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

        # fail is true, so we do not permit False Positives
        self._test_issue(rule, code, expected, fail=True)

    def test_precision_recall(self):
        location = os.path.join("tests", "data", "principle_rules.csv")

        if not os.path.exists(location):
            pytest.skip("Cannot access private test data")

        principle_rules = pandas.read_csv(location)
        for code, test_col in (
            ("P000", "labelled.no_proxy"),
            ("P001", "labelled.success"),
            ("P002", "labelled.thresholded"),
            ("P003", "labelled.exceptions"),
            ("P004", "labelled.generalized_match_content"),
            ("P005", "labelled.generalized_match_location"),
        ):
            y_pred_list = []
            for rule in principle_rules["rule.rule"]:
                parsed_rule = idstools.rule.parse(rule)
                y_pred_list.append(self.check_issue(parsed_rule, code, True)[0])

            y_true = numpy.array(principle_rules[test_col].to_numpy() == 0)
            y_pred = numpy.array(y_pred_list)

            precision = float(
                sklearn.metrics.precision_score(y_true, y_pred, zero_division=0)  # type: ignore reportArgumentType
            )
            recall = float(
                sklearn.metrics.recall_score(y_true, y_pred, zero_division=1)  # type: ignore reportArgumentType
            )

            fp_mask = ~y_true & y_pred
            fn_mask = y_true & ~y_pred

            for rule in principle_rules.loc[fp_mask, "rule.rule"]:
                _logger.debug(
                    "Code {} False Positive: {}".format(code, rule)  # noqa: G001
                )

            for rule in principle_rules.loc[fn_mask, "rule.rule"]:
                _logger.debug(
                    "Code {} False Negative: {}".format(code, rule)  # noqa: G001
                )

            _logger.info(
                "Code {}\tPrecision: {}\tRecall: {}".format(  # noqa: G001
                    code, precision, recall
                )
            )


def __main__():
    pytest.main()
