import logging
import os
import shutil
import sys
import urllib.request
import warnings

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import suricata_check
from click.testing import CliRunner

regex_provider = suricata_check.utils.get_regex_provider()

ET_OPEN_URLS = {
    "v4": "https://rules.emergingthreats.net/open-nogpl/suricata-4.0/emerging-all.rules",
    "v5": "https://rules.emergingthreats.net/open-nogpl/suricata-5.0/emerging-all.rules",
    "v7": "https://rules.emergingthreats.net/open-nogpl/suricata-7.0.3/emerging-all.rules",
}
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
@pytest.mark.parametrize(("version", "et_open_url"), ET_OPEN_URLS.items())
def test_main_cli_integration_et_open(version, et_open_url):
    # Retrieve the latest ET Open rules if not present.
    if not os.path.exists(f"tests/data/emerging-all-{version}.rules"):
        urllib.request.urlretrieve(
            et_open_url, f"tests/data/emerging-all-{version}.rules"
        )

    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            f"--rules=tests/data/emerging-all-{version}.rules",
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
            "--log-level=DEBUG",
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
    logging.basicConfig(level=logging.DEBUG)
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                "--rules=tests/data/test_error.rules",
                "--out=tests/data/out",
                "--log-level=DEBUG",
            ),
        )

    assert excinfo.value.code == 0


def test_get_checkers():
    logging.basicConfig(level=logging.DEBUG)
    suricata_check.get_checkers()


def test_analyze_rule():
    logging.basicConfig(level=logging.DEBUG)
    rule = idstools.rule.parse(
        """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
    )

    suricata_check.analyze_rule(rule)


def test_version():
    logging.basicConfig(level=logging.DEBUG)
    if not hasattr(suricata_check, "__version__"):
        pytest.fail("suricata_check has no attribute __version__")
    from suricata_check._version import __version__
    if __version__ == "unknown":
        warnings.warn(RuntimeWarning("Version is unknown."))


def _check_log_file():
    log_file = "tests/data/out/suricata-check.log"

    if not os.path.exists(log_file):
        warnings.warn(RuntimeWarning("No log file found."))
        return

    with open(log_file) as log_fh:
        for line in log_fh.readlines():
            if regex_provider.match(
                r".+ - .+ - (ERROR|CRITICAL) - .+(?<!Error parsing rule)",
                line,
            ):
                pytest.fail(line)
            if regex_provider.match(r".+ - .+ - (WARNING) - .+", line):
                warnings.warn(RuntimeWarning(line))


def __main__():
    pytest.main()
