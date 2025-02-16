import logging
import os
import shutil
import sys
import tarfile
import urllib.request
import warnings
from collections.abc import Iterable, Sequence
from typing import Callable

import idstools.rule
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import suricata_check
from click.testing import CliRunner

_regex_provider = suricata_check.utils.regex.get_regex_provider()

ET_OPEN_URLS = {
    "v5": "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules.tar.gz",
    "v7": "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.tar.gz",
}
SNORT_COMMUNITY_URL = (
    "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
)


@pytest.fixture(autouse=True)
def __run_around_tests():
    # Clean up from previous tests.
    if os.path.exists("tests/data/out") and os.path.isdir("tests/data/out"):
        for f in os.listdir("tests/data/out"):
            os.remove(os.path.join("tests/data/out", f))

    yield

    # Optionally clean up after the test run.
    logging.shutdown()


@pytest.mark.serial()
def test_main_cli():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        ("--rules=tests/data/test.rules", "--out=tests/data/out", "--log-level=DEBUG"),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_single_rule():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
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

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_gitlab():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/test.rules",
            "--out=tests/data/out",
            "--log-level=DEBUG",
            "--gitlab",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_github():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/test.rules",
            "--out=tests/data/out",
            "--log-level=DEBUG",
            "--github",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_evaluate_disabled():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/test.rules",
            "--out=tests/data/out",
            "--log-level=DEBUG",
            "--evaluate-disabled",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_issue_severity():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/test.rules",
            "--out=tests/data/out",
            "--log-level=DEBUG",
            "--issue-severity=WARNING",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_include_all():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/test.rules",
            "--out=tests/data/out",
            "--log-level=DEBUG",
            "--include-all",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_include():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/test.rules",
            "--out=tests/data/out",
            "--log-level=DEBUG",
            "--include=M.*",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.serial()
def test_main_cli_exclude():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            "--rules=tests/data/test.rules",
            "--out=tests/data/out",
            "--log-level=DEBUG",
            "--exclude=M.*",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.slow()
@pytest.mark.serial()
@pytest.hookimpl(trylast=True)
@pytest.mark.parametrize(("version", "et_open_url"), ET_OPEN_URLS.items())
def test_main_cli_integration_et_open(version, et_open_url):
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"

    # Retrieve the latest ET Open rules if not present.
    if not os.path.exists(f"tests/data/emerging-all-{version}.rules"):
        if not os.path.exists(f"tests/data/emerging-all-{version}.rules.tar.gz"):
            urllib.request.urlretrieve(
                et_open_url,
                f"tests/data/emerging-all-{version}.rules.tar.gz",
            )

        tarfile.open(f"tests/data/emerging-all-{version}.rules.tar.gz").extract(
            "emerging-all.rules",
            "tests/data/temp",
        )
        os.remove(f"tests/data/emerging-all-{version}.rules.tar.gz")
        shutil.move(
            "tests/data/temp/emerging-all.rules",
            f"tests/data/emerging-all-{version}.rules",
        )
        shutil.rmtree("tests/data/temp")

    runner = CliRunner()
    result = runner.invoke(
        suricata_check.main,
        (
            f"--rules=tests/data/emerging-all-{version}.rules",
            "--out=tests/data/out",
            "--log-level=INFO",
        ),
        catch_exceptions=False,
    )

    __check_log_file()

    if result.exit_code != 0:
        pytest.fail(result.output)


@pytest.mark.slow()
@pytest.mark.serial()
@pytest.hookimpl(trylast=True)
def test_main_cli_integration_snort_community():
    # Retrieve the latest Snort rules if not present.
    if not os.path.exists("tests/data/snort3-community.rules"):
        if not os.path.exists("tests/data/snort3-community-rules.tar.gz"):
            urllib.request.urlretrieve(
                SNORT_COMMUNITY_URL,
                "tests/data/snort3-community-rules.tar.gz",
            )

        tarfile.open("tests/data/snort3-community-rules.tar.gz").extract(
            "snort3-community-rules/snort3-community.rules",
            "tests/data/temp",
        )
        os.remove("tests/data/snort3-community-rules.tar.gz")
        shutil.move(
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
            "--log-level=INFO",
        ),
        catch_exceptions=False,
    )

    if result.exit_code != 0:
        pytest.fail(result.output)

    # We do not check the log file as we know some Snort rules are invalid Suricata rules.


@pytest.mark.serial()
def test_main():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                "--rules=tests/data/test.rules",
                "--out=tests/data/out",
                "--log-level=DEBUG",
            ),
        )

    __check_log_file()

    assert excinfo.value.code == 0


@pytest.mark.serial()
def test_main_single_rule():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                """--single-rule=alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
                "--out=tests/data/out",
                "--log-level=DEBUG",
            ),
        )

    __check_log_file()

    assert excinfo.value.code == 0


@pytest.mark.serial()
def test_main_ini():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                "--rules=tests/data/test.rules",
                "--out=tests/data/out",
                "--log-level=DEBUG",
                "--ini=tests/data/suricata-check.ini",
            ),
        )

    __check_log_file()

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


@pytest.mark.serial()
def test_main_ignore():
    os.environ["SURICATA_CHECK_FORCE_LOGGING"] = "TRUE"
    with pytest.raises(SystemExit) as excinfo:
        suricata_check.main(
            (
                "--rules=tests/data/test_ignore.rules",
                "--out=tests/data/out",
                "--log-level=DEBUG",
            ),
        )

    __check_log_file()
    __check_fast_file([lambda line: "M001" not in line], [lambda file: "M000" in file])

    assert excinfo.value.code == 0


def test_get_checkers():
    logging.basicConfig(level=logging.DEBUG)
    suricata_check.get_checkers()


def test_get_checkers_multiple_include():
    logging.basicConfig(level=logging.DEBUG)
    assert len(suricata_check.get_checkers(include=("M.*", "S.*"))) > 0


def test_get_checkers_include():
    logging.basicConfig(level=logging.DEBUG)
    assert len(suricata_check.get_checkers(include=("M.*",))) == 1


def test_get_checkers_exclude():
    logging.basicConfig(level=logging.DEBUG)
    assert len(suricata_check.get_checkers(exclude=("(?!M).*",))) == 1


def test_analyze_rule():
    logging.basicConfig(level=logging.DEBUG)
    rule = idstools.rule.parse(
        """alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1;)""",
    )
    assert rule is not None

    suricata_check.analyze_rule(rule)


def test_version():
    logging.basicConfig(level=logging.DEBUG)
    if not hasattr(suricata_check, "__version__"):
        pytest.fail("suricata_check has no attribute __version__")
    from suricata_check._version import __version__

    if __version__ == "unknown":
        warnings.warn(RuntimeWarning("Version is unknown."))


def __check_log_file(checks: Iterable[Callable[[str], bool]] = []):
    log_file = "tests/data/out/suricata-check.log"

    if not os.path.exists(log_file):
        pytest.fail("No log file found.")
        return

    with open(log_file) as log_fh:
        for line in log_fh.readlines():
            if _regex_provider.match(
                r".+ - .+ - (ERROR|CRITICAL) - .+(?<!Error parsing rule)",
                line,
            ):
                pytest.fail(line)
            for check in checks:
                if not check(line):
                    pytest.fail(line)
            if _regex_provider.match(r".+ - .+ - (WARNING) - .+", line):
                warnings.warn(RuntimeWarning(line))


def __check_fast_file(
    line_checks: Sequence[Callable[[str], bool]] = [],
    file_checks: Sequence[Callable[[str], bool]] = [],
):
    log_file = "tests/data/out/suricata-check-fast.log"

    if not os.path.exists(log_file):
        pytest.fail("No fast file found.")
        return

    if len(line_checks) > 0:
        with open(log_file) as log_fh:
            for line in log_fh.readlines():
                for check in line_checks:
                    if not check(line):
                        pytest.fail(line)

    if len(file_checks) > 0:
        with open(log_file) as log_fh:
            file = "\n".join(log_fh.readlines())
            for check in file_checks:
                if not check(file):
                    pytest.fail(file)


def __main__():
    pytest.main()
