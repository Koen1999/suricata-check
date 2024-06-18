import os
import re
import sys
from typing import Optional

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

REGEX_PROVIDER = suricata_check.utils.get_regex_provider()


def test_rule_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            for raw in (line, rule["raw"]):
                match = suricata_check.utils.RULE_REGEX.match(raw)
                if match is None:
                    pytest.fail(raw)

                # If we extracted a rule, idstools should still be able to parse it.
                try:
                    new_rule: Optional[idstools.rule.Rule] = idstools.rule.parse(
                        match.group(0),
                    )
                except:
                    pytest.fail(raw)

                if new_rule is None:
                    pytest.fail(raw)


def test_header_regex():
    regex = REGEX_PROVIDER.compile(r"(\s*#)?\s*([^\(\)]*)\(.*\)")
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            for raw in (line, rule["raw"]):
                match = regex.match(raw)
                assert match is not None
                extracted = match.group(2).strip()
                new_match = suricata_check.utils.HEADER_REGEX.match(
                    extracted,
                )
                if new_match is None:
                    pytest.fail(extracted)
                if new_match.group(0) == "alert":
                    pytest.fail(extracted)


def test_body_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        regex = REGEX_PROVIDER.compile(r"^[#a-zA-Z0-9:\$_\.\-<>\s]+(\(.*\))\s*(#.*)?$")
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            for raw in (line, rule["raw"]):
                match = regex.match(
                    raw,
                )
                if match is None:
                    pytest.fail(raw)
                group = match.group(1)
                if group is None:
                    pytest.fail(raw)
                extracted = group.strip()
                new_match = suricata_check.utils.BODY_REGEX.match(
                    extracted,
                )
                if new_match is None:
                    pytest.fail(extracted)


def test_action_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            raw = rule["action"]
            if suricata_check.utils.ACTION_REGEX.match(raw) is None:
                pytest.fail(raw)


def test_direction_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            raw = rule["direction"]
            if suricata_check.utils.DIRECTION_REGEX.match(raw) is None:
                pytest.fail(raw)


def test_addr_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            for raw in (rule["source_addr"], rule["dest_addr"]):
                if suricata_check.utils.ADDR_REGEX.match(raw) is None:
                    pytest.fail(raw)


def test_port_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            for raw in (rule["source_port"], rule["dest_port"]):
                if suricata_check.utils.PORT_REGEX.match(raw) is None:
                    pytest.fail(raw)


def test_option_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        for line in rules_fh.readlines():
            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)
            except:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            if rule is None:
                # If idstools cannot parse it, we assume it is not a rule
                continue

            # Ensure our regular expressions are correct
            for name, value in [t.values() for t in rule["options"]]:
                for raw in (
                    f"{name}: {value};",
                    f"{name}:{value};",
                    f"{name}:{value} ;",
                    f"{name}: {value} ;",
                ):
                    match = suricata_check.utils.OPTION_REGEX.match(raw)
                    if match is None:
                        pytest.fail(raw)
                    if match.group(0) == "sid":
                        pytest.fail(raw)


def __main__():
    pytest.main()
