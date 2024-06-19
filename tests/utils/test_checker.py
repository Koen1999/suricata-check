import os
import sys

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check


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
        result = suricata_check.utils.get_rule_option_positions(rule, name)
        if tuple(sorted(result)) != tuple(sorted(expected)):
            pytest.fail(str((name, expected, result, rule["raw"])))


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
        result = suricata_check.utils.get_rule_option_position(rule, name)
        if result != expected:
            pytest.fail(str((name, expected, result, rule["raw"])))


def test_get_rule_options_positions():
    rule = idstools.rule.parse(
        """alert tcp $HOME_NET any -> $EXTERNAL_NET any (\
msg:"Test"; \
content:"test"; \
content:"test"; \
sid:1;)""",
    )

    names = ["msg", "content", "pcre"]
    expected = [0, 1, 2]

    result = suricata_check.utils.get_rule_options_positions(rule, names)
    if tuple(sorted(result)) != tuple(sorted(expected)):
        pytest.fail(str((names, expected, result, rule["raw"])))


def __main__():
    pytest.main()
