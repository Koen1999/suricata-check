"""The `suricata_check.suricata_check` module contains the command line utility and the main program logic."""

import io
import logging
import os
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

from suricata_check import __version__  # noqa: E402
from suricata_check.checkers.interface import CheckerInterface  # noqa: E402
from suricata_check.utils._click import ClickHandler  # noqa: E402
from suricata_check.utils._path import find_rules_file  # noqa: E402
from suricata_check.utils.checker import check_rule_option_recognition  # noqa: E402
from suricata_check.utils.typing import (  # noqa: E402
    EXTENSIVE_SUMMARY_TYPE,
    ISSUES_TYPE,
    RULE_REPORTS_TYPE,
    RULE_SUMMARY_TYPE,
    SIMPLE_SUMMARY_TYPE,
    OutputReport,
    OutputSummary,
    RuleReport,
)

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]

logger = logging.getLogger(__name__)


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
)
def main(
    out: str = ".",
    rules: str = ".",
    single_rule: Optional[str] = None,
    log_level: LogLevel = "DEBUG",
    evaluate_disabled: bool = False,
) -> None:
    """Processes all rules inside a rules file and outputs a list of issues found.

    Args:
    ----
    out: A path to a directory where the output will be written.
    rules: A path to a Suricata rules file or a directory in which a single rule file can be discovered
    single_rule: A single Suricata rule to be checked. If set, the rules file will be ignored.
    log_level: The verbosity level for logging.
    evaluate_disabled: A flag indicating whether disabled rules should be evaluated.

    Raises:
    ------
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

    # Setup logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=(
            logging.FileHandler(
                filename=os.path.join(out, "suricata-check.log"),
                delay=True,
            ),
            ClickHandler(),
        ),
        force=os.environ.get("SURICATA_CHECK_FORCE_LOGGING", False) == "TRUE",
    )

    # Log the arguments:
    logger.info("Running suricata-check with the following arguments:")
    logger.info("out: %s", out)
    logger.info("rules: %s", rules)
    logger.info("single_rule: %s", single_rule)
    logger.info("log_level: %s", log_level)
    logger.info("evaluate_disabled: %s", evaluate_disabled)

    logger.debug("Platform: %s", sys.platform)
    logger.debug("Python version: %s", sys.version)
    logger.debug("suricata-check path: %s", _suricata_check_path)
    logger.debug("suricata-check version: %s", __version__)

    checkers = get_checkers()

    if single_rule is not None:
        rule: Optional[idstools.rule.Rule] = idstools.rule.parse(single_rule)

        # Verify that a rule was parsed correctly.
        if rule is None:
            msg = f"Error parsing rule from user input: {single_rule}"
            logger.critical(msg)
            raise click.BadParameter(f"Error: {msg}")

        logger.debug("Processing rule: %i", rule["sid"])

        check_rule_option_recognition(rule)

        rule_report = analyze_rule(rule, checkers=checkers)

        _write_output(OutputReport(rules=[rule_report]), out)

        # Return here so no rules file is processed.
        return

    # Check if the rules argument is valid and find the rules file
    rules = find_rules_file(rules)

    output = process_rules_file(rules, evaluate_disabled, checkers=checkers)

    _write_output(output, out)


def _write_output(
    output: OutputReport,
    out: str,
) -> None:
    logger.info(
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

            stats_fh.write(
                tabulate.tabulate(
                    overall_summary.items(),
                    headers=("Count",),
                )
                + "\n\n",
            )

            click.secho(f"Total issues found: {overall_summary['Total Issues']}", color=True, bold=True, fg="blue")
            click.secho(f"Rules with Issues found: {overall_summary['Rules with Issues']}", color=True, bold=True, fg="blue")

            issues_by_group: SIMPLE_SUMMARY_TYPE = summary.issues_by_group

            stats_fh.write(
                tabulate.tabulate(
                    issues_by_group.items(),
                    headers=("Count",),
                )
                + "\n\n",
            )

            issues_by_type: EXTENSIVE_SUMMARY_TYPE = summary.issues_by_type
            for checker, checker_issues_by_type in issues_by_type.items():
                stats_fh.write(" " + checker + " " + "\n")
                stats_fh.write("-" * (len(checker) + 2) + "\n")
                stats_fh.write(
                    tabulate.tabulate(
                        checker_issues_by_type.items(),
                        headers=("Count",),
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
    ----
    rules: A path to a Suricata rules file.
    evaluate_disabled: A flag indicating whether disabled rules should be evaluated.
    checkers: The checkers to be used when processing the rule file.

    Returns:
    -------
    A list of rules and their issues.

    Raises:
    ------
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
            logger.error(msg)
            raise RuntimeError(msg)

        logger.info("Processing rule file: %s", rules)

        for number, line in enumerate(rules_fh.readlines(), start=1):
            if line.startswith("#"):
                if evaluate_disabled:
                    # Verify that this line is a rule and not a comment
                    if idstools.rule.parse(line) is None:
                        # Log the comment since it may be a invalid rule
                        logger.warning("Ignoring comment on line %i: %i", number, line)
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
                logger.error("Error parsing rule on line %i: %i", number, line)
                continue

            logger.debug("Processing rule: %i on line %i", rule["sid"], number)

            check_rule_option_recognition(rule)

            rule_report: RuleReport = analyze_rule(
                rule,
                checkers=checkers,
            )
            rule_report.line = number
            output.rules.append(rule_report)

    logger.info("Completed processing rule file: %s", rules)

    output.summary = __summarize_output(output)

    return output


@lru_cache(maxsize=1)
def get_checkers() -> Sequence[CheckerInterface]:
    """Auto discovers all available checkers that implement the CheckerInterface.

    Returns
    -------
    A list of available checkers that implement the CheckerInterface.

    """
    checkers: list[CheckerInterface] = []
    for checker in CheckerInterface.__subclasses__():
        checkers.append(checker())

    logger.info(
        "Discovered checkers: [%s]",
        ", ".join([c.__class__.__name__ for c in checkers]),
    )

    # Perform a uniqueness check on the codes emmitted by the checkers
    for checker1 in checkers:
        for checker2 in checkers:
            if checker1 == checker2:
                continue
            if not set(checker1.codes).isdisjoint(checker2.codes):
                msg = f"Checker {checker1.__class__.__name__} and {checker2.__class__.__name__} have overlapping codes."
                logger.error(msg)

    return sorted(checkers, key=lambda x: x.__class__.__name__)


def analyze_rule(
    rule: idstools.rule.Rule,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> RuleReport:
    """Checks a rule and returns a dictionary containing the rule and a list of issues found.

    Args:
    ----
    rule: The rule to be checked.
    checkers: The checkers to be used to check the rule.

    Returns:
    -------
    A list of issues found in the rule.
    Each issue is typed as a `dict`.

    """
    if checkers is None:
        checkers = get_checkers()

    rule_report: RuleReport = RuleReport(rule=rule)

    for checker in checkers:
        rule_report.add_issues(checker.check_rule(rule))

    rule_report.summary = __summarize_rule(rule_report)

    return rule_report


def __summarize_rule(
    rule: RuleReport,
) -> RULE_SUMMARY_TYPE:
    """Summarizes the issues found in a rule.

    Args:
    ----
    rule: The rule output dictionary to be summarized.

    Returns:
    -------
    A dictionary containing a summary of all issues found in the rule.

    """
    summary = {}

    issues: ISSUES_TYPE = rule.issues
    summary["total_issues"] = len(issues)
    summary["issues_by_group"] = defaultdict(int)
    for issue in issues:
        checker = issue.checker
        summary["issues_by_group"][checker] += 1

    # Ensure also checkers without issues are included in the report.
    for checker in get_checkers():
        if checker.__class__.__name__ not in summary["issues_by_group"]:
            summary["issues_by_group"][checker.__class__.__name__] = 0

    # Sort dictionaries for deterministic output
    summary["issues_by_group"] = __sort_mapping(summary["issues_by_group"])

    return summary


def __summarize_output(
    output: OutputReport,
) -> OutputSummary:
    """Summarizes the issues found in a rules file.

    Args:
    ----
    output: The unsammarized output of the rules file containing all rules and their issues.

    Returns:
    -------
    A dictionary containing a summary of all issues found in the rules file.

    """
    return OutputSummary(
        overall_summary=__get_overall_summary(output),
        issues_by_group=__get_issues_by_group(output),
        issues_by_type=__get_issues_by_type(output),
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
) -> SIMPLE_SUMMARY_TYPE:
    issues_by_group = defaultdict(int)

    # Ensure also checkers and codes without issues are included in the report.
    for checker in get_checkers():
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
) -> EXTENSIVE_SUMMARY_TYPE:
    issues_by_type: EXTENSIVE_SUMMARY_TYPE = defaultdict(lambda: defaultdict(int))

    # Ensure also checkers and codes without issues are included in the report.
    for checker in get_checkers():
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
