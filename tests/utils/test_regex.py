import os
import sys
from typing import Optional

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

_regex_provider = suricata_check.utils.regex.get_regex_provider()


@pytest.hookimpl(tryfirst=True)
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
                match = suricata_check.utils.regex._RULE_REGEX.match(raw)  # type: ignore reportPrivateUsage # noqa: SLF001
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


@pytest.hookimpl(tryfirst=True)
def test_header_regex():
    regex = _regex_provider.compile(r"(\s*#)?\s*([^\(\)]*)\(.*\)")
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
                new_match = suricata_check.utils.regex.HEADER_REGEX.match(
                    extracted,
                )
                if new_match is None:
                    pytest.fail(extracted)
                if new_match.group(0) == "alert":
                    pytest.fail(extracted)


@pytest.hookimpl(tryfirst=True)
def test_body_regex():
    with (open(os.path.normpath("tests/data/test.rules")) as rules_fh,):
        regex = _regex_provider.compile(r"^[#a-zA-Z0-9:\$_\.\-<>\s]+(\(.*\))\s*(#.*)?$")
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
                new_match = suricata_check.utils.regex._BODY_REGEX.match(  # type: ignore reportPrivateUsage # noqa: SLF001
                    extracted,
                )
                if new_match is None:
                    pytest.fail(extracted)


@pytest.hookimpl(tryfirst=True)
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
            if suricata_check.utils.regex._ACTION_REGEX.match(raw) is None:  # type: ignore reportPrivateUsage # noqa: SLF001
                pytest.fail(raw)


@pytest.hookimpl(tryfirst=True)
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
            if suricata_check.utils.regex._DIRECTION_REGEX.match(raw) is None:  # type: ignore reportPrivateUsage # noqa: SLF001
                pytest.fail(raw)


@pytest.hookimpl(tryfirst=True)
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
                if suricata_check.utils.regex._ADDR_REGEX.match(raw) is None:  # type: ignore reportPrivateUsage # noqa: SLF001
                    pytest.fail(raw)


@pytest.hookimpl(tryfirst=True)
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
                if suricata_check.utils.regex._PORT_REGEX.match(raw) is None:  # type: ignore reportPrivateUsage # noqa: SLF001
                    pytest.fail(raw)


@pytest.hookimpl(tryfirst=True)
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
                    match = suricata_check.utils.regex._OPTION_REGEX.match(raw)  # type: ignore reportPrivateUsage # noqa: SLF001
                    if match is None:
                        pytest.fail(raw)
                    if match.group(0) == "sid":
                        pytest.fail(raw)


def __main__():
    pytest.main()
