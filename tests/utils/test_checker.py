import os
import sys
from collections.abc import Iterable

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check


@pytest.hookimpl(tryfirst=True)
def test_get_rule_option_positions():
    rule = idstools.rule.parse(
        """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
content:"test"; \
sid:1;)""",
    )

    for name, expected in (
        ("msg", [0]),
        ("content", [1, 2]),
        ("sid", [3]),
        ("pcre", []),
    ):
        result = suricata_check.utils.checker.get_rule_option_positions(rule, name)
        if tuple(sorted(result)) != tuple(sorted(expected)):
            pytest.fail(str((name, expected, result, rule["raw"])))


@pytest.hookimpl(tryfirst=True)
@pytest.mark.parametrize(
    ("seperator_keywords", "expected_sequences"),
    [
        (
            suricata_check.utils.regex.BUFFER_KEYWORDS,
            {
                (
                    "content",
                    "depth",
                    "content",
                    "distance",
                    "within",
                    "byte_jump",
                    "byte_jump",
                    "byte_jump",
                    "byte_extract",
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                ),
            },
        ),
        (
            suricata_check.utils.regex.CONTENT_KEYWORDS,
            {
                (
                    "content",
                    "depth",
                ),
                (
                    "content",
                    "distance",
                    "within",
                    "byte_jump",
                    "byte_jump",
                    "byte_jump",
                    "byte_extract",
                ),
                (
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                ),
                (
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                ),
                (
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                ),
                (
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                ),
                (
                    "content",
                    "distance",
                    "within",
                    "isdataat",
                    "byte_jump",
                ),
            },
        ),
    ],
)
def test_get_rule_detection_options_sequences(
    seperator_keywords: Iterable[str], expected_sequences: set[tuple[str]]
):
    rule = idstools.rule.parse(
        """alert tls $EXTERNAL_NET any -> $HTTP_SERVERS 443 (\
msg:"KOEN HUNTING Inbound HTTPS (HTTP/TLS) Client Hello without Server Name Indication (SNI)"; \
flow:established,to_server; \
content:"|16 03|"; depth:2; \
content:"|01|"; distance:3; within:1; \
byte_jump:1, 37, relative, big; \
byte_jump:2, 0, relative, big; \
byte_jump:1, 0, relative, big; \
byte_extract:2, 0, ext_len, relative, big; \
content:!"|00 00|"; distance:0; within:2; \
isdataat:1, relative; \
byte_jump:2, 2, relative, big; \
content:!"|00 00|"; distance:0; within:2; \
isdataat:1, relative; \
byte_jump:2, 2, relative, big; \
content:!"|00 00|"; distance:0; within:2; \
isdataat:1, relative; byte_jump:2, 2, relative, big; \
content:!"|00 00|"; distance:0; within:2; \
isdataat:1, relative; \
byte_jump:2, 2, relative, big; \
content:!"|00 00|"; distance:0; within:2; \
isdataat:1, relative; \
byte_jump:2, 2, relative, big; \
xbits:isset,koen_supports_sni,track ip_dst; \
xbits:isnotset,koen_supports_sni_domain,track ip_dst; \
xbits:isnotset,koen_supports_sni_ipv4,track ip_dst; \
threshold:type both,track by_both,count 1,seconds 3600; \
target:dest_ip; \
reference:url,koen.teuwen.net/report/tls-web-attack-detection; \
classtype:non-standard-protocol; priority:2; gid:1999; sid:1999012; rev:1; \
metadata:affected_product Any, attack_target Client_Endpoint, created_at 2024_03_06, deployment Perimeter, \
performance_impact Low, signature_severity Minor;)""",
    )

    sequences = {
        tuple(sequence)
        for sequence in suricata_check.utils.checker.get_rule_keyword_sequences(
            rule, seperator_keywords=seperator_keywords
        )
    }

    for sequence in sequences:
        if sequence not in expected_sequences:
            pytest.fail(
                str(("Unexpected sequence", sequence, expected_sequences, rule["raw"]))
            )

    for expected_sequence in expected_sequences:
        if expected_sequence not in sequences:
            pytest.fail(
                str(("Sequence not found", expected_sequence, sequences, rule["raw"]))
            )


@pytest.hookimpl(tryfirst=True)
def test_get_rule_option_position():
    rule = idstools.rule.parse(
        """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
content:"test"; \
sid:1;)""",
    )

    for name, expected in (
        ("msg", 0),
        ("sid", 3),
        ("pcre", None),
    ):
        result = suricata_check.utils.checker.get_rule_option_position(rule, name)
        if result != expected:
            pytest.fail(str((name, expected, result, rule["raw"])))


@pytest.hookimpl(tryfirst=True)
def test__get_rule_options_positions():
    rule = idstools.rule.parse(
        """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
content:"test"; \
sid:1;)""",
    )

    names = ["msg", "content", "pcre"]
    expected = [0, 1, 2]

    result = suricata_check.utils.checker.get_rule_options_positions(rule, names)
    if tuple(sorted(result)) != tuple(sorted(expected)):
        pytest.fail(str((names, expected, result, rule["raw"])))


def __main__():
    pytest.main()
