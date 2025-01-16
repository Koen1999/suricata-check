"""The `suricata_check.suricata_check` module contains the command line utility and the main program logic."""

import atexit
import io
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
    Literal,
    Optional,
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
from suricata_check.utils._click import ClickHandler  # noqa: E402
from suricata_check.utils._path import find_rules_file  # noqa: E402
from suricata_check.utils.checker import check_rule_option_recognition  # noqa: E402
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

_logger = logging.getLogger(__name__)

_regex_provider = get_regex_provider()

# Global variable to check if extensions have already been imported in case get_checkers() is called multiple times.
suricata_check_extensions_imported = False


@click.command()
@click.option(
    "--out",
    "-o",
    default=".",
    help="Path to suricata-check output folder.",
    show_default=True,
)
@click.option(
    "--rules",
    "-r",
    default=".",
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
    "--log-level",
    default="INFO",
    help=f"Verbosity level for logging. Can be one of {LOG_LEVELS}",
    show_default=True,
)
@click.option(
    "--evaluate-disabled",
    default=False,
    help="Flag to evaluate disabled rules.",
    show_default=True,
    is_flag=True,
)
@click.option(
    "--include-all",
    "-a",
    default=False,
    help="Flag to indicate all checker codes should be enabled.",
    show_default=True,
    is_flag=True,
)
@click.option(
    "--include",
    "-i",
    default=(),
    help="List of all checker codes to enable.",
    show_default=True,
    multiple=True,
)
@click.option(
    "--exclude",
    "-e",
    default=(),
    help="List of all checker codes to disable.",
    show_default=True,
    multiple=True,
)
def main(  # noqa: PLR0913
    out: str = ".",
    rules: str = ".",
    single_rule: Optional[str] = None,
    log_level: LogLevel = "DEBUG",
    evaluate_disabled: bool = False,
    include_all: bool = False,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
) -> None:
    """The `suricata-check` command processes all rules inside a rules file and outputs a list of detected issues.

    Raises:
      BadParameter: If provided arguments are invalid.

      RuntimeError: If no checkers could be automatically discovered.

    """
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

    click_handler = ClickHandler()
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
    _logger.info("evaluate_disabled: %s", evaluate_disabled)
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

    checkers = get_checkers(include, exclude)

    if single_rule is not None:
        __main_single_rule(out, single_rule, checkers)

        # Return here so no rules file is processed.
        _at_exit()
        return

    # Check if the rules argument is valid and find the rules file
    rules = find_rules_file(rules)

    output = process_rules_file(rules, evaluate_disabled, checkers=checkers)

    __write_output(output, out)

    _at_exit()


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
            line: Optional[int] = rule_report.line
            issues: ISSUES_TYPE = rule_report.issues
            for issue in issues:
                code = issue.code
                issue_msg = issue.message.replace("\n", " ")

                msg = f"[{code}] Line {line}, sid {rule['sid']}: {issue_msg}"
                fast_fh.write(msg + "\n")
                click.secho(msg, color=True, fg="blue")

    if output.summary is not None:
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


def process_rules_file(
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

        for number, line in enumerate(rules_fh.readlines(), start=1):
            if line.startswith("#"):
                if evaluate_disabled:
                    # Verify that this line is a rule and not a comment
                    if idstools.rule.parse(line) is None:
                        # Log the comment since it may be a invalid rule
                        _logger.warning("Ignoring comment on line %i: %s", number, line)
                        continue
                else:
                    # Skip the rule
                    continue

            # Skip whitespace
            if len(line.strip()) == 0:
                continue

            rule: Optional[idstools.rule.Rule] = idstools.rule.parse(line)

            # Verify that a rule was parsed correctly.
            if rule is None:
                _logger.error("Error parsing rule on line %i: %s", number, line)
                continue

            if not is_valid_rule(rule):
                _logger.error("Invalid rule on line %i: %s", number, line)
                continue

            _logger.debug("Processing rule: %s on line %i", rule["sid"], number)

            rule_report: RuleReport = analyze_rule(
                rule,
                checkers=checkers,
            )
            rule_report.line = number
            output.rules.append(rule_report)

    _logger.info("Completed processing rule file: %s", rules)

    output.summary = __summarize_output(output, checkers)

    return output


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

        enabled, relevant_codes = __get_checker_enabled(checker, include, exclude)

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
) -> tuple[bool, set[str]]:
    enabled = checker.enabled_by_default

    relevant_codes = set(checker.codes)

    if len(include) > 0:
        for regex in include:
            relevant_codes = set(
                filter(
                    lambda code: _regex_provider.compile("^" + regex + "$").match(code)
                    is not None,
                    relevant_codes,
                )
            )
            if len(relevant_codes) > 0:
                enabled = True
    for regex in exclude:
        relevant_codes = set(
            filter(
                lambda code: _regex_provider.compile("^" + regex + "$").match(code)
                is None,
                relevant_codes,
            )
        )

    if len(relevant_codes) == 0:
        enabled = False

    return enabled, relevant_codes


def analyze_rule(
    rule: idstools.rule.Rule,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> RuleReport:
    """Checks a rule and returns a dictionary containing the rule and a list of issues found.

    Args:
    rule: The rule to be checked.
    checkers: The checkers to be used to check the rule.

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

    for checker in checkers:
        rule_report.add_issues(checker.check_rule(rule))

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
