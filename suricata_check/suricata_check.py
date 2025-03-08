"""The `suricata_check.suricata_check` module contains the command line utility and the main program logic."""

import atexit
import configparser
import io
import json
import logging
import logging.handlers
import multiprocessing
import os
import pkgutil
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from functools import lru_cache
from typing import (
    Any,
    Literal,
    Optional,
    TypeVar,
    Union,
    overload,
)

import click
import idstools.rule
import tabulate

# Add suricata-check to the front of the PATH, such that the version corresponding to the CLI is used.
_suricata_check_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if sys.path[0] != _suricata_check_path:
    sys.path.insert(0, _suricata_check_path)

from suricata_check import __version__, get_dependency_versions  # noqa: E402
from suricata_check.checkers.interface import CheckerInterface  # noqa: E402
from suricata_check.checkers.interface.dummy import DummyChecker  # noqa: E402
from suricata_check.utils._click import ClickHandler, ClickHelpOption  # noqa: E402
from suricata_check.utils._path import find_rules_file  # noqa: E402
from suricata_check.utils.checker import check_rule_option_recognition, get_rule_suboption  # noqa: E402
from suricata_check.utils.checker_typing import (  # noqa: E402
    EXTENSIVE_SUMMARY_TYPE,
    ISSUES_TYPE,
    RULE_REPORTS_TYPE,
    RULE_SUMMARY_TYPE,
    SIMPLE_SUMMARY_TYPE,
    InvalidRuleError,
    OutputReport,
    OutputSummary,
    RuleReport,
    get_all_subclasses,
)
from suricata_check.utils.regex import get_regex_provider, is_valid_rule  # noqa: E402

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
GITLAB_SEVERITIES = {
    logging.DEBUG: "info",
    logging.INFO: "info",
    logging.WARNING: "minor",
    logging.ERROR: "major",
    logging.CRITICAL: "critical",
}
GITHUB_SEVERITIES = {
    logging.DEBUG: "debug",
    logging.INFO: "notice",
    logging.WARNING: "warning",
    logging.ERROR: "error",
    logging.CRITICAL: "error",
}
GITHUB_COMMAND = (
    "::{level} file={file},line={line},endLine={end_line},title={title}::{message}"
)

_logger = logging.getLogger(__name__)

_regex_provider = get_regex_provider()

# Global variable to check if extensions have already been imported in case get_checkers() is called multiple times.
suricata_check_extensions_imported = False


@click.command()
@click.option(
    "--ini",
    "-i",
    help="Path to suricata-check.ini file to read configuration from.",
    show_default=True,
)
@click.option(
    "--rules",
    "-r",
    help="Path to Suricata rules to provide check on.",
    show_default=True,
)
@click.option(
    "--single-rule",
    "-s",
    help="A single Suricata rule to be checked",
    show_default=False,
)
@click.option(
    "--out",
    "-o",
    help="Path to suricata-check output folder.",
    show_default=True,
)
@click.option(
    "--log-level",
    help=f"Verbosity level for logging. Can be one of {LOG_LEVELS}",
    show_default=True,
)
@click.option(
    "--gitlab",
    help="Flag to create CodeClimate output report for GitLab CI/CD.",
    show_default=True,
    is_flag=True,
)
@click.option(
    "--github",
    help="Flag to write workflow commands to stdout for GitHub CI/CD.",
    show_default=True,
    is_flag=True,
)
@click.option(
    "--evaluate-disabled",
    help="Flag to evaluate disabled rules.",
    show_default=True,
    is_flag=True,
)
@click.option(
    "--issue-severity",
    help=f"Verbosity level for detected issues. Can be one of {LOG_LEVELS}",
    show_default=True,
)
@click.option(
    "--include-all",
    "-a",
    help="Flag to indicate all checker codes should be enabled.",
    show_default=True,
    is_flag=True,
)
@click.option(
    "--include",
    "-i",
    help="List of all checker codes to enable.",
    show_default=True,
    multiple=True,
)
@click.option(
    "--exclude",
    "-e",
    help="List of all checker codes to disable.",
    show_default=True,
    multiple=True,
)
@click.help_option("-h", "--help", cls=ClickHelpOption)
def main(  # noqa: PLR0915
    **kwargs: dict[str, Any],
) -> None:
    """The `suricata-check` command processes all rules inside a rules file and outputs a list of detected issues.

    Raises:
      BadParameter: If provided arguments are invalid.

      RuntimeError: If no checkers could be automatically discovered.

    """
    # Look for a ini file and parse it.
    ini_kwargs = __get_ini_kwargs(
        str(kwargs["ini"]) if kwargs["ini"] is not None else None  # type: ignore reportUnnecessaryComparison
    )

    # Verify CLI argument types and get CLI arguments or use default arguments
    rules: str = __get_verified_kwarg([kwargs, ini_kwargs], "rules", str, False, ".")
    single_rule: Optional[str] = __get_verified_kwarg(
        [kwargs, ini_kwargs], "single_rule", str, True, None
    )
    out: str = __get_verified_kwarg([kwargs, ini_kwargs], "out", str, False, ".")
    log_level: LogLevel = __get_verified_kwarg(
        [kwargs, ini_kwargs], "log_level", str, False, "DEBUG"
    )
    gitlab: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "gitlab", bool, False, False
    )
    github: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "github", bool, False, False
    )
    evaluate_disabled: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "evaluate_disabled", bool, False, False
    )
    issue_severity: LogLevel = __get_verified_kwarg(
        [kwargs, ini_kwargs], "issue_severity", str, False, "INFO"
    )
    include_all: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "include_all", bool, False, False
    )
    include: tuple[str, ...] = __get_verified_kwarg(
        [kwargs, ini_kwargs], "include", tuple, False, ()
    )
    exclude: tuple[str, ...] = __get_verified_kwarg(
        [kwargs, ini_kwargs], "exclude", tuple, False, ()
    )

    # Verify that out argument is valid
    if os.path.exists(out) and not os.path.isdir(out):
        raise click.BadParameter(f"Error: {out} is not a directory.")

    # Verify that log_level argument is valid
    if log_level not in LOG_LEVELS:
        raise click.BadParameter(f"Error: {log_level} is not a valid log level.")

    # Create out directory if non-existent
    if not os.path.exists(out):
        os.makedirs(out)

    # Setup logging from a seperate thread
    queue = multiprocessing.Manager().Queue()
    queue_handler = logging.handlers.QueueHandler(queue)

    click_handler = ClickHandler(
        github=github, github_level=getattr(logging, log_level)
    )
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=(queue_handler, click_handler),
        force=os.environ.get("SURICATA_CHECK_FORCE_LOGGING", False) == "TRUE",
    )

    file_handler = logging.FileHandler(
        filename=os.path.join(out, "suricata-check.log"),
        delay=True,
    )
    queue_listener = logging.handlers.QueueListener(
        queue,
        file_handler,
        respect_handler_level=True,
    )

    def _at_exit() -> None:
        """Cleans up logging listener and handlers before exiting."""
        queue_listener.enqueue_sentinel()
        queue_listener.stop()
        file_handler.flush()
        file_handler.close()
        atexit.unregister(_at_exit)

    atexit.register(_at_exit)

    queue_listener.start()

    # Log the arguments:
    _logger.info("Running suricata-check with the following arguments:")
    _logger.info("out: %s", out)
    _logger.info("rules: %s", rules)
    _logger.info("single_rule: %s", single_rule)
    _logger.info("log_level: %s", log_level)
    _logger.info("gitlab: %s", gitlab)
    _logger.info("github: %s", github)
    _logger.info("evaluate_disabled: %s", evaluate_disabled)
    _logger.info("issue_severity: %s", issue_severity)
    _logger.info("include_all: %s", include_all)
    _logger.info("include: %s", include)
    _logger.info("exclude: %s", exclude)

    # Log the environment:
    _logger.debug("Platform: %s", sys.platform)
    _logger.debug("Python version: %s", sys.version)
    _logger.debug("suricata-check path: %s", _suricata_check_path)
    _logger.debug("suricata-check version: %s", __version__)
    for package, version in get_dependency_versions().items():
        _logger.debug("Dependency %s version: %s", package, version)

    # Verify that include and exclude arguments are valid
    if include_all and len(include) > 0:
        raise click.BadParameter(
            "Error: Cannot use --include-all and --include together."
        )
    if include_all:
        include = (".*",)

    # Verify that issue_severity argument is valid
    if issue_severity not in LOG_LEVELS:
        raise click.BadParameter(
            f"Error: {issue_severity} is not a valid issue severity or log level."
        )

    checkers = get_checkers(
        include, exclude, issue_severity=getattr(logging, issue_severity)
    )

    if single_rule is not None:
        __main_single_rule(out, single_rule, checkers)

        # Return here so no rules file is processed.
        _at_exit()
        return

    # Check if the rules argument is valid and find the rules file
    rules = find_rules_file(rules)

    output = process_rules_file(rules, evaluate_disabled, checkers=checkers)

    __write_output(output, out, gitlab=gitlab, github=github, rules_file=rules)

    _at_exit()


def __get_ini_kwargs(path: Optional[str]) -> dict[str, Any]:  # noqa: C901, PLR0912
    ini_kwargs: dict[str, Any] = {}
    if path is not None:
        if not os.path.exists(path):
            raise click.BadParameter(
                f"Error: INI file provided in {path} but no options loaded"
            )

    # Use the default path if no path was provided
    if path is None:
        path = "suricata-check.ini"
        if not os.path.exists(path):
            return {}

    config_parser = configparser.ConfigParser(
        empty_lines_in_values=False,
        default_section="suricata-check",
        converters={"tuple": lambda x: tuple(json.loads(x))},
    )
    config_parser.read(path)
    ini_kwargs = {}

    if config_parser.has_option("suricata-check", "rules"):
        ini_kwargs["rules"] = config_parser.get("suricata-check", "rules")
    if config_parser.has_option("suricata-check", "out"):
        ini_kwargs["out"] = config_parser.get("suricata-check", "out")
    if config_parser.has_option("suricata-check", "log"):
        ini_kwargs["log"] = config_parser.get("suricata-check", "log")
    if config_parser.has_option("suricata-check", "gitlab"):
        ini_kwargs["gitlab"] = config_parser.getboolean("suricata-check", "gitlab")
    if config_parser.has_option("suricata-check", "github"):
        ini_kwargs["github"] = config_parser.getboolean("suricata-check", "github")
    if config_parser.has_option("suricata-check", "evaluate_disabled"):
        ini_kwargs["evaluate_disabled"] = config_parser.getboolean(
            "suricata-check", "evaluate_disabled"
        )
    if config_parser.has_option("suricata-check", "issue-severity"):
        ini_kwargs["issue_severity"] = config_parser.get(
            "suricata-check", "issue-severity"
        )
    if config_parser.has_option("suricata-check", "include-all"):
        ini_kwargs["include_all"] = config_parser.getboolean(
            "suricata-check", "include-all"
        )
    if config_parser.has_option("suricata-check", "include"):
        ini_kwargs["include"] = config_parser.gettuple("suricata-check", "include")  # type: ignore reportAttributeAccessIssue
    if config_parser.has_option("suricata-check", "exclude"):
        ini_kwargs["exclude"] = config_parser.gettuple("suricata-check", "exclude")  # type: ignore reportAttributeAccessIssue

    return ini_kwargs


D = TypeVar("D")


@overload
def __get_verified_kwarg(
    kwargss: Sequence[dict[str, Any]],
    name: str,
    expected_type: type,
    optional: Literal[True],
    default: D,
) -> Optional[D]:
    pass


@overload
def __get_verified_kwarg(
    kwargss: Sequence[dict[str, Any]],
    name: str,
    expected_type: type,
    optional: Literal[False],
    default: D,
) -> D:
    pass


def __get_verified_kwarg(
    kwargss: Sequence[dict[str, Any]],
    name: str,
    expected_type: type,
    optional: bool,
    default: D,
) -> Optional[D]:
    for kwargs in kwargss:
        if name in kwargs:
            if kwargs[name] is None:
                if optional and default is not None:
                    return None
                return default

            if kwargs[name] is not default:
                if not isinstance(kwargs[name], expected_type):
                    raise click.BadParameter(
                        f"""Error: \
                Argument `{name}` should have a value of type `{expected_type}` \
                but has value {kwargs[name]} of type {kwargs[name].__class__} instead."""
                    )
                return kwargs[name]

    return default


def __main_single_rule(
    out: str, single_rule: str, checkers: Optional[Sequence[CheckerInterface]]
) -> None:
    rule: Optional[idstools.rule.Rule] = idstools.rule.parse(single_rule)

    # Verify that a rule was parsed correctly.
    if rule is None:
        msg = f"Error parsing rule from user input: {single_rule}"
        _logger.critical(msg)
        raise click.BadParameter(f"Error: {msg}")

    if not is_valid_rule(rule):
        msg = f"Error parsing rule from user input: {single_rule}"
        _logger.critical(msg)
        raise click.BadParameter(f"Error: {msg}")

    _logger.debug("Processing rule: %s", rule["sid"])

    rule_report = analyze_rule(rule, checkers=checkers)

    __write_output(OutputReport(rules=[rule_report]), out)


def __write_output(
    output: OutputReport,
    out: str,
    gitlab: bool = False,
    github: bool = False,
    rules_file: Optional[str] = None,
) -> None:
    _logger.info(
        "Writing output to suricata-check.jsonl and suricata-check-fast.log in %s",
        os.path.abspath(out),
    )
    with (
        open(
            os.path.join(out, "suricata-check.jsonl"),
            "w",
            buffering=io.DEFAULT_BUFFER_SIZE,
        ) as jsonl_fh,
        open(
            os.path.join(out, "suricata-check-fast.log"),
            "w",
            buffering=io.DEFAULT_BUFFER_SIZE,
        ) as fast_fh,
    ):
        rules: RULE_REPORTS_TYPE = output.rules
        jsonl_fh.write("\n".join([str(rule) for rule in rules]))

        for rule_report in rules:
            rule: idstools.rule.Rule = rule_report.rule
            lines: str = (
                "{}-{}".format(rule_report.line_begin, rule_report.line_end)
                if rule_report.line_begin
                else "Unknown"
            )
            issues: ISSUES_TYPE = rule_report.issues
            for issue in issues:
                code = issue.code
                severity = (
                    logging.getLevelName(issue.severity) if issue.severity else None
                )
                issue_msg = issue.message.replace("\n", " ")

                msg = "[{}]{} Lines {}, sid {}: {}".format(
                    code,
                    f" ({severity})" if severity else "",
                    lines,
                    rule["sid"],
                    issue_msg,
                )
                fast_fh.write(msg + "\n")
                click.secho(msg, color=True, fg="blue")

    if output.summary is not None:
        __write_output_stats(output, out)

    if gitlab:
        assert rules_file is not None

        __write_output_gitlab(output, out, rules_file)

    if github:
        assert rules_file is not None

        __write_output_github(output, rules_file)


def __write_output_stats(output: OutputReport, out: str) -> None:
    assert output.summary is not None

    with open(
        os.path.join(out, "suricata-check-stats.log"),
        "w",
        buffering=io.DEFAULT_BUFFER_SIZE,
    ) as stats_fh:
        summary: OutputSummary = output.summary

        overall_summary: SIMPLE_SUMMARY_TYPE = summary.overall_summary

        n_issues = overall_summary["Total Issues"]
        n_rules = (
            overall_summary["Rules with Issues"]
            + overall_summary["Rules without Issues"]
        )

        stats_fh.write(
            tabulate.tabulate(
                (
                    (
                        k,
                        v,
                        (
                            "{:.0%}".format(v / n_rules)
                            if k.startswith("Rules ") and n_rules > 0
                            else "-"
                        ),
                    )
                    for k, v in overall_summary.items()
                ),
                headers=(
                    "Count",
                    "Percentage of Rules",
                ),
            )
            + "\n\n",
        )

        click.secho(
            f"Total issues found: {overall_summary['Total Issues']}",
            color=True,
            bold=True,
            fg="blue",
        )
        click.secho(
            f"Rules with Issues found: {overall_summary['Rules with Issues']}",
            color=True,
            bold=True,
            fg="blue",
        )

        issues_by_group: SIMPLE_SUMMARY_TYPE = summary.issues_by_group

        stats_fh.write(
            tabulate.tabulate(
                (
                    (k, v, "{:.0%}".format(v / n_issues) if n_issues > 0 else "-")
                    for k, v in issues_by_group.items()
                ),
                headers=(
                    "Count",
                    "Percentage of Total Issues",
                ),
            )
            + "\n\n",
        )

        issues_by_type: EXTENSIVE_SUMMARY_TYPE = summary.issues_by_type
        for checker, checker_issues_by_type in issues_by_type.items():
            stats_fh.write(" " + checker + " " + "\n")
            stats_fh.write("-" * (len(checker) + 2) + "\n")
            stats_fh.write(
                tabulate.tabulate(
                    (
                        (
                            k,
                            v,
                            "{:.0%}".format(v / n_rules) if n_rules > 0 else "-",
                        )
                        for k, v in checker_issues_by_type.items()
                    ),
                    headers=(
                        "Count",
                        "Percentage of Rules",
                    ),
                )
                + "\n\n",
            )


def __write_output_gitlab(output: OutputReport, out: str, rules_file: str) -> None:
    with open(
        os.path.join(out, "suricata-check-gitlab.json"),
        "w",
        buffering=io.DEFAULT_BUFFER_SIZE,
    ) as gitlab_fh:
        issue_dicts = []
        for rule_report in output.rules:
            line_begin: Optional[int] = rule_report.line_begin
            assert line_begin is not None
            line_end: Optional[int] = rule_report.line_end
            assert line_end is not None
            issues: ISSUES_TYPE = rule_report.issues
            for issue in issues:
                code = issue.code
                issue_msg = issue.message.replace("\n", " ")
                assert issue.checker is not None
                issue_checker = issue.checker
                issue_hash = str(issue.hash)
                assert issue.severity is not None
                issue_severity = GITLAB_SEVERITIES[issue.severity]

                issue_dict: Mapping[
                    str,
                    Union[str, list[str], Mapping[str, Union[str, Mapping[str, int]]]],
                ] = {
                    "description": issue_msg,
                    "categories": [issue_checker],
                    "check_name": f"Suricata Check {code}",
                    "fingerprint": issue_hash,
                    "severity": issue_severity,
                    "location": {
                        "path": rules_file,
                        "lines": {"begin": line_begin, "end": line_end},
                    },
                }
                issue_dicts.append(issue_dict)

        gitlab_fh.write(json.dumps(issue_dicts))


def __write_output_github(output: OutputReport, rules_file: str) -> None:
    output_lines: dict[str, list[str]] = {
        k: [] for k in set(GITHUB_SEVERITIES.values())
    }
    for rule_report in output.rules:
        line_begin: Optional[int] = rule_report.line_begin
        assert line_begin is not None
        line_end: Optional[int] = rule_report.line_end
        assert line_end is not None
        issues: ISSUES_TYPE = rule_report.issues
        for issue in issues:
            code = issue.code
            issue_msg = issue.message.replace("\n", " ")
            assert issue.checker is not None
            issue_checker = issue.checker
            assert issue.severity is not None
            issue_severity = GITHUB_SEVERITIES[issue.severity]
            title = f"{issue_checker} - {code}"

            output_lines[issue_severity].append(
                GITHUB_COMMAND.format(
                    level=issue_severity,
                    file=rules_file,
                    line=line_begin,
                    end_line=line_end,
                    title=title,
                    message=issue_msg,
                )
            )

    for message_level, lines in output_lines.items():
        if len(lines) > 0:
            print(f"::group::{message_level}")  # noqa: T201
            for message in lines:
                print(message)  # noqa: T201
            print("::endgroup::")  # noqa: T201


def process_rules_file(  # noqa: C901, PLR0912, PLR0915
    rules: str,
    evaluate_disabled: bool,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> OutputReport:
    """Processes a rule file and returns a list of rules and their issues.

    Args:
    rules: A path to a Suricata rules file.
    evaluate_disabled: A flag indicating whether disabled rules should be evaluated.
    checkers: The checkers to be used when processing the rule file.

    Returns:
        A list of rules and their issues.

    Raises:
        RuntimeError: If no checkers could be automatically discovered.

    """
    if checkers is None:
        checkers = get_checkers()

    output = OutputReport()

    with (
        open(
            os.path.normpath(rules),
            buffering=io.DEFAULT_BUFFER_SIZE,
        ) as rules_fh,
    ):
        if len(checkers) == 0:
            msg = "No checkers provided for processing rules."
            _logger.error(msg)
            raise RuntimeError(msg)

        _logger.info("Processing rule file: %s", rules)

        collected_multiline_parts: Optional[str] = None
        multiline_begin_number: Optional[int] = None

        for number, line in enumerate(rules_fh.readlines(), start=1):
            # First work on collecting and parsing multiline rules
            if line.rstrip("\r\n").endswith("\\"):
                multiline_part = line.rstrip("\r\n")[:-1]

                if collected_multiline_parts is None:
                    collected_multiline_parts = multiline_part
                    multiline_begin_number = number
                else:
                    collected_multiline_parts += multiline_part.lstrip()

                continue

            # Process final part of multiline rule if one is being collected
            if collected_multiline_parts is not None:
                collected_multiline_parts += line.lstrip()

                rule_line = collected_multiline_parts.strip()

                collected_multiline_parts = None
            # If no multiline rule is being collected process as a potential single line rule
            else:
                if len(line.strip()) == 0:
                    continue

                if line.strip().startswith("#"):
                    if evaluate_disabled:
                        # Verify that this line is a rule and not a comment
                        if idstools.rule.parse(line) is None:
                            # Log the comment since it may be a invalid rule
                            _logger.warning(
                                "Ignoring comment on line %i: %s", number, line
                            )
                            continue
                    else:
                        # Skip the rule
                        continue

                rule_line = line.strip()

            try:
                rule: Optional[idstools.rule.Rule] = idstools.rule.parse(rule_line)
            except Exception:  # noqa: BLE001
                _logger.error(
                    "Internal error in idstools parsing rule on line %i: %s",
                    number,
                    rule_line,
                )
                rule = None

            # Parse comment and potential ignore comment to ignore rules
            ignore = __parse_type_ignore(rule)

            # Verify that a rule was parsed correctly.
            if rule is None:
                _logger.error("Error parsing rule on line %i: %s", number, rule_line)
                continue

            if not is_valid_rule(rule):
                _logger.error("Invalid rule on line %i: %s", number, rule_line)
                continue

            _logger.debug("Processing rule: %s on line %i", rule["sid"], number)

            rule_report: RuleReport = analyze_rule(
                rule,
                checkers=checkers,
                ignore=ignore,
            )
            rule_report.line_begin = multiline_begin_number or number
            rule_report.line_end = number

            output.rules.append(rule_report)

            multiline_begin_number = None

    _logger.info("Completed processing rule file: %s", rules)

    output.summary = __summarize_output(output, checkers)

    return output


def __is_valid_idstools_rule(text: str) -> bool:
    try:
        rule: Optional[idstools.rule.Rule] = idstools.rule.parse(text)
    except Exception:  # noqa: BLE001
        return False

    if rule is None:
        return False

    return True


def __parse_type_ignore(
    rule: Optional[idstools.rule.Rule] 
) -> Optional[Sequence[str]]:
    if rule is None:
        return None

    ignore_value = get_rule_suboption(rule, "metadata", "suricata-check")
    if ignore_value is None:
        return []

    return ignore_value.strip(' "').split(",")


def _import_extensions() -> None:
    global suricata_check_extensions_imported  # noqa: PLW0603
    if suricata_check_extensions_imported is True:
        return

    for module in pkgutil.iter_modules():
        if module.name.startswith("suricata_check_"):
            try:
                imported_module = __import__(module.name)
                _logger.info(
                    "Detected and successfully imported suricata-check extension %s with version %s.",
                    module.name.replace("_", "-"),
                    getattr(imported_module, "__version__"),
                )
            except ImportError:
                _logger.warning(
                    "Detected potential suricata-check extension %s but failed to import it.",
                    module.name.replace("_", "-"),
                )
    suricata_check_extensions_imported = True


@lru_cache(maxsize=1)
def get_checkers(
    include: Sequence[str] = (".*",),
    exclude: Sequence[str] = (),
    issue_severity: int = logging.INFO,
) -> Sequence[CheckerInterface]:
    """Auto discovers all available checkers that implement the CheckerInterface.

    Returns:
    A list of available checkers that implement the CheckerInterface.

    """
    # Check for extensions and try to import them
    _import_extensions()

    checkers: list[CheckerInterface] = []
    for checker in get_all_subclasses(CheckerInterface):
        if checker.__name__ == DummyChecker.__name__:
            continue

        # Initialize DummyCheckers to retrieve error messages.
        if issubclass(checker, DummyChecker):
            checker()

        enabled, relevant_codes = __get_checker_enabled(
            checker, include, exclude, issue_severity
        )

        if enabled:
            checkers.append(checker(include=relevant_codes))

        else:
            _logger.info("Checker %s is disabled.", checker.__name__)

    _logger.info(
        "Discovered and enabled checkers: [%s]",
        ", ".join([c.__class__.__name__ for c in checkers]),
    )
    if len(checkers) == 0:
        _logger.warning(
            "No checkers were enabled. Check the include and exclude arguments."
        )

    # Perform a uniqueness check on the codes emmitted by the checkers
    for checker1 in checkers:
        for checker2 in checkers:
            if checker1 == checker2:
                continue
            if not set(checker1.codes).isdisjoint(checker2.codes):
                msg = f"Checker {checker1.__class__.__name__} and {checker2.__class__.__name__} have overlapping codes."
                _logger.error(msg)

    return sorted(checkers, key=lambda x: x.__class__.__name__)


def __get_checker_enabled(
    checker: type[CheckerInterface],
    include: Sequence[str],
    exclude: Sequence[str],
    issue_severity: int,
) -> tuple[bool, set[str]]:
    enabled = checker.enabled_by_default

    # If no include regexes are provided, include all by default
    if len(include) == 0:
        relevant_codes = set(checker.codes.keys())
    else:
        # If include regexes are provided, include all codes that match any of these regexes
        relevant_codes = set()

        for regex in include:
            relevant_codes.update(
                set(
                    filter(
                        lambda code: _regex_provider.compile("^" + regex + "$").match(
                            code
                        )
                        is not None,
                        checker.codes.keys(),
                    )
                )
            )

        if len(relevant_codes) > 0:
            enabled = True

    # Now remove the codes that are excluded according to any of the provided exclude regexes
    for regex in exclude:
        relevant_codes = set(
            filter(
                lambda code: _regex_provider.compile("^" + regex + "$").match(code)
                is None,
                relevant_codes,
            )
        )

    # Now filter out irrelevant codes based on severity
    relevant_codes = set(
        filter(
            lambda code: checker.codes[code]["severity"] >= issue_severity,
            relevant_codes,
        )
    )

    if len(relevant_codes) == 0:
        enabled = False

    return enabled, relevant_codes


def analyze_rule(
    rule: idstools.rule.Rule,
    checkers: Optional[Sequence[CheckerInterface]] = None,
    ignore: Optional[Sequence[str]] = None,
) -> RuleReport:
    """Checks a rule and returns a dictionary containing the rule and a list of issues found.

    Args:
    rule: The rule to be checked.
    checkers: The checkers to be used to check the rule.
    ignore: Regular expressions to match checker codes to ignore

    Returns:
    A list of issues found in the rule.
    Each issue is typed as a `dict`.

    Raises:
    InvalidRuleError: If the rule does not follow the Suricata syntax.

    """
    if not is_valid_rule(rule):
        raise InvalidRuleError(rule["raw"])

    check_rule_option_recognition(rule)

    if checkers is None:
        checkers = get_checkers()

    rule_report: RuleReport = RuleReport(rule=rule)

    _logger.warning(ignore)

    compiled_ignore = (
        [_regex_provider.compile(r) for r in ignore] if ignore is not None else []
    )

    for checker in checkers:
        try:
            issues = checker.check_rule(rule)
            for r in compiled_ignore:
                issues = list(filter(lambda issue: r.match(issue.code) is None, issues))
            rule_report.add_issues(issues)
        except Exception as exception:  # noqa: BLE001
            _logger.warning(
                "Failed to run %s on rule: %s",
                checker.__class__.__name__,
                rule["raw"],
                extra={"exception": exception},
            )

    rule_report.summary = __summarize_rule(rule_report, checkers)

    return rule_report


def __summarize_rule(
    rule: RuleReport,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> RULE_SUMMARY_TYPE:
    """Summarizes the issues found in a rule.

    Args:
    rule: The rule output dictionary to be summarized.
    checkers: The checkers to be used to check the rule.

    Returns:
    A dictionary containing a summary of all issues found in the rule.

    """
    if checkers is None:
        checkers = get_checkers()

    summary = {}

    issues: ISSUES_TYPE = rule.issues
    summary["total_issues"] = len(issues)
    summary["issues_by_group"] = defaultdict(int)
    for issue in issues:
        checker = issue.checker
        summary["issues_by_group"][checker] += 1

    # Ensure also checkers without issues are included in the report.
    for checker in checkers:
        if checker.__class__.__name__ not in summary["issues_by_group"]:
            summary["issues_by_group"][checker.__class__.__name__] = 0

    # Sort dictionaries for deterministic output
    summary["issues_by_group"] = __sort_mapping(summary["issues_by_group"])

    return summary


def __summarize_output(
    output: OutputReport,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> OutputSummary:
    """Summarizes the issues found in a rules file.

    Args:
    output: The unsammarized output of the rules file containing all rules and their issues.
    checkers: The checkers to be used to check the rule.

    Returns:
    A dictionary containing a summary of all issues found in the rules file.

    """
    if checkers is None:
        checkers = get_checkers()

    return OutputSummary(
        overall_summary=__get_overall_summary(output),
        issues_by_group=__get_issues_by_group(output, checkers),
        issues_by_type=__get_issues_by_type(output, checkers),
    )


def __get_overall_summary(
    output: OutputReport,
) -> SIMPLE_SUMMARY_TYPE:
    overall_summary = {
        "Total Issues": 0,
        "Rules with Issues": 0,
        "Rules without Issues": 0,
    }

    rules: RULE_REPORTS_TYPE = output.rules
    for rule in rules:
        issues: ISSUES_TYPE = rule.issues
        overall_summary["Total Issues"] += len(issues)

        if len(issues) == 0:
            overall_summary["Rules without Issues"] += 1
        else:
            overall_summary["Rules with Issues"] += 1

    return overall_summary


def __get_issues_by_group(
    output: OutputReport,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> SIMPLE_SUMMARY_TYPE:
    if checkers is None:
        checkers = get_checkers()

    issues_by_group = defaultdict(int)

    # Ensure also checkers and codes without issues are included in the report.
    for checker in checkers:
        issues_by_group[checker.__class__.__name__] = 0

    rules: RULE_REPORTS_TYPE = output.rules
    for rule in rules:
        issues: ISSUES_TYPE = rule.issues

        for issue in issues:
            checker = issue.checker
            if checker is not None:
                issues_by_group[checker] += 1

    return __sort_mapping(issues_by_group)


def __get_issues_by_type(
    output: OutputReport,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> EXTENSIVE_SUMMARY_TYPE:
    if checkers is None:
        checkers = get_checkers()
    issues_by_type: EXTENSIVE_SUMMARY_TYPE = defaultdict(lambda: defaultdict(int))

    # Ensure also checkers and codes without issues are included in the report.
    for checker in checkers:
        for code in checker.codes:
            issues_by_type[checker.__class__.__name__][code] = 0

    rules: RULE_REPORTS_TYPE = output.rules
    for rule in rules:
        issues: ISSUES_TYPE = rule.issues

        checker_codes = defaultdict(lambda: defaultdict(int))
        for issue in issues:
            checker = issue.checker
            if checker is not None:
                code = issue.code
                checker_codes[checker][code] += 1

        for checker, codes in checker_codes.items():
            for code, count in codes.items():
                issues_by_type[checker][code] += count

    for key in issues_by_type:
        issues_by_type[key] = __sort_mapping(issues_by_type[key])

    return __sort_mapping(issues_by_type)


def __sort_mapping(mapping: Mapping) -> dict:
    return {key: mapping[key] for key in sorted(mapping.keys())}


if __name__ == "__main__":
    main()
