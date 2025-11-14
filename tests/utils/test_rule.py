import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check


@pytest.hookimpl(tryfirst=True)
def test_parse_too_much_whitespace():
    rule_str = """alert http $EXTERNAL_NET any  -> $HOME_NET any (msg:"Too much whitespace in header"; sid:1;)"""
    rule = suricata_check.utils.rule.parse(rule_str)

    if rule is None:
        pytest.fail(f"Failed to parse rule: {rule_str}")
