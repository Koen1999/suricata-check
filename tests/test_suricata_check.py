import logging
import os
import re
import shutil
import sys
import urllib.request
import warnings

import idstools.rule
import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import suricata_check

REGEX_PROVIDER = suricata_check.utils.get_regex_provider()

ET_OPEN_URL = (
    "https://rules.emergingthreats.net/open-nogpl/suricata-5.0/emerging-all.rules"
)
SNORT_COMMUNITY_URL = (
    "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
)


@pytest.fixture(autouse=True)
def _run_around_tests():
    # Clean up from previous tests.
    if os.path.exists("tests/data/out") and os.path.isdir("tests/data/out"):
        for f in os.listdir("tests/data/out"):
            os.remove(os.path.join("tests/data/out", f))

    yield

    # Optionally clean up after the test run.
    logging.shutdown()


@pytest.mark.serial()
def test_main_cli():
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        ("--rules=tests/data/test.rules", "--out=tests/data/out", "--log-level=DEBUG"),
        catch_exceptions=False,
    )

    _check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_single_rule():
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            """--single-rule=alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
            "--out=tests/data/out",
            "--log-level=DEBUG",
        ),
        catch_exceptions=False,
    )

    _check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.slow()
@pytest.mark.serial()
@pytest.hookimpl(trylast=True)
def test_main_cli_integration_et_open():
    # Retrieve the latest ET Open rules if not present.
    if not os.path.exists("tests/data/emerging-all.rules"):
        urllib.request.urlretrieve(ET_OPEN_URL, "tests/data/emerging-all.rules")

    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/emerging-all.rules",
            "--out=tests/data/out",
            "--log-level=WARNING",
        ),
        catch_exceptions=False,
    )

    _check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.slow()
@pytest.mark.serial()
@pytest.hookimpl(trylast=True)
def test_main_cli_integration_snort_community():
    # Retrieve the latest ET Open rules if not present.
    if not os.path.exists("tests/data/snort3-community-rules.tar.gz"):
        urllib.request.urlretrieve(
            SNORT_COMMUNITY_URL,
            "tests/data/snort3-community-rules.tar.gz",
        )

    if not os.path.exists("tests/data/snort3-community.rules"):
        shutil.unpack_archive(
            "tests/data/snort3-community-rules.tar.gz",
            "tests/data/temp",
        )
        shutil.copyfile(
            "tests/data/temp/snort3-community-rules/snort3-community.rules",
            "tests/data/snort3-community.rules",
        )
        shutil.rmtree("tests/data/temp")

    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/snort3-community.rules",
            "--out=tests/data/out",
            "--log-level=WARNING",
        ),
        catch_exceptions=False,
    )

    if result.exit_code != 0:
        pytest.fail(result.output)

    # We do not check the log file as we know some Snort rules are invalid Suricata rules.


@pytest.mark.serial()
def test_main():
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                "--rules=tests/data/test.rules",
                "--out=tests/data/out",
                "--log-level=DEBUG",
            ),
        )

    _check_log_file()

    assert excinfo.value.code == 0


@pytest.mark.serial()
def test_main_single_rule():
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                """--single-rule=alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
                "--out=tests/data/out",
                "--log-level=DEBUG",
            ),
        )

    _check_log_file()

    assert excinfo.value.code == 0


@pytest.mark.serial()
def test_main_error():
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                "--rules=tests/data/test_error.rules",
                "--out=tests/data/out",
                "--log-level=DEBUG",
            ),
        )

    assert excinfo.value.code == 0

    # We do not check the log file as we know some Snort rules are invalid Suricata rules.


def test_get_checkers():
    suricata_check.get_checkers()


def test_analyze_rule():
    rule = idstools.rule.parse(
        """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
    )

    suricata_check.analyze_rule(rule)


def _check_log_file():
    with open("tests/data/out/suricata-check.log") as log_fh:
        for line in log_fh.readlines():
            if REGEX_PROVIDER.match(
                r".+ - .+ - (ERROR|CRITICAL) - .+(?<!Error parsing rule)",
                line,
            ):
                pytest.fail(line)
            if REGEX_PROVIDER.match(r".+ - .+ - (WARNING) - .+", line):
                warnings.warn(RuntimeWarning(line))


def __main__():
    pytest.main()
