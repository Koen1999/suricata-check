"""The `suricata_check.suricata_check` module contains the command line utility and the main program logic."""

import io
import logging
import os
import sys
from collections import defaultdict
from collections.abc import Sequence
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
from suricata_check.utils import (  # noqa: E402
    EXTENSIVE_SUMMARY_TYPE,
    ISSUES_TYPE,
    OUTPUT_REPORT_TYPE,
    OUTPUT_SUMMARY_TYPE,
    RULE_REPORT_TYPE,
    RULE_REPORTS_TYPE,
    RULE_SUMMARY_TYPE,
    SIMPLE_SUMMARY_TYPE,
    check_rule_option_recognition,
    find_rules_file,
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
            logging.StreamHandler(stream=click.get_text_stream("stdout")),
        ),
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

        rule_dict = analyze_rule(rule, checkers=checkers)

        _write_output({"rules": [rule_dict]}, out)

        # Return here so no rules file is processed.
        return

    # Check if the rules argument is valid and find the rules file
    rules = find_rules_file(rules)

    output = process_rules_file(rules, evaluate_disabled, checkers=checkers)

    _write_output(output, out)


def _write_output(
    output: OUTPUT_REPORT_TYPE,
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
        rules: RULE_REPORTS_TYPE = output["rules"]  # type: ignore reportAssignmentType
        jsonl_fh.write("\n".join([str(rule) for rule in rules]))

        for rule_dict in rules:
            rule: idstools.rule.Rule = rule_dict["rule"]  # type: ignore reportAssignmentType
            line: Optional[int] = rule_dict["line"] if "line" in rule_dict else None  # type: ignore reportAssignmentType
            issues: ISSUES_TYPE = rule_dict["issues"]  # type: ignore reportAssignmentType
            for issue in issues:
                code = issue["code"]
                issue_msg = issue["message"].replace("\n", " ")

                msg = f"[{code}] Line {line}, sid {rule['sid']}: {issue_msg}"
                fast_fh.write(msg + "\n")
                click.echo(msg)

    if "summary" in output:
        with open(
            os.path.join(out, "suricata-check-stats.log"),
            "w",
            buffering=io.DEFAULT_BUFFER_SIZE,
        ) as stats_fh:
            summary: OUTPUT_SUMMARY_TYPE = output["summary"]  # type: ignore reportAssignmentType

            overall_summary: SIMPLE_SUMMARY_TYPE = summary["overall_summary"]  # type: ignore reportAssignmentType

            stats_fh.write(
                tabulate.tabulate(
                    overall_summary.items(),
                    headers=("Count",),
                )
                + "\n\n",
            )

            click.echo(f"Total issues found: {overall_summary['Total Issues']}")
            click.echo(
                f"Rules with Issues found: {overall_summary['Rules with Issues']}",
            )

            issues_by_group: SIMPLE_SUMMARY_TYPE = summary["issues_by_group"]  # type: ignore reportAssignmentType

            stats_fh.write(
                tabulate.tabulate(
                    issues_by_group.items(),
                    headers=("Count",),
                )
                + "\n\n",
            )

            issues_by_type: EXTENSIVE_SUMMARY_TYPE = summary["issues_by_type"]  # type: ignore reportAssignmentType
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
) -> OUTPUT_REPORT_TYPE:
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

    output: OUTPUT_REPORT_TYPE = {"rules": []}

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

            dict_out: RULE_REPORT_TYPE = analyze_rule(
                rule,
                checkers=checkers,
            )
            dict_out["line"] = number
            output["rules"].append(dict_out)  # type: ignore reportAttributeAccessIssue

    logger.info("Completed processing rule file: %s", rules)

    output["summary"] = __summarize_output(output)  # type: ignore reportArgumentType

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
) -> RULE_REPORT_TYPE:
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

    dict_out: RULE_REPORT_TYPE = {
        "rule": rule,
    }

    issues: ISSUES_TYPE = []
    for checker in checkers:
        issues += checker.check_rule(rule)

    dict_out["issues"] = issues

    dict_out["summary"] = __summarize_rule(dict_out)

    return dict_out


def __summarize_rule(
    rule: RULE_REPORT_TYPE,
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

    issues: ISSUES_TYPE = rule["issues"]  # type: ignore reportAssignmentType
    summary["total_issues"] = len(issues)
    summary["issues_by_group"] = defaultdict(int)
    for issue in issues:
        checker = issue["checker"]
        summary["issues_by_group"][checker] += 1

    # Ensure also checkers without issues are included in the report.
    for checker in get_checkers():
        if checker.__class__.__name__ not in summary["issues_by_group"]:
            summary["issues_by_group"][checker.__class__.__name__] = 0

    # Sort dictionaries for deterministic output
    summary["issues_by_group"] = {
        key: summary["issues_by_group"][key]
        for key in sorted(summary["issues_by_group"].keys())
    }

    return summary


def __summarize_output(
    output: OUTPUT_SUMMARY_TYPE,
) -> OUTPUT_SUMMARY_TYPE:
    """Summarizes the issues found in a rules file.

    Args:
    ----
    output: The unsammarized output of the rules file containing all rules and their issues.

    Returns:
    -------
    A dictionary containing a summary of all issues found in the rules file.

    """
    summary: OUTPUT_SUMMARY_TYPE = {}

    summary["overall_summary"] = {
        "Total Issues": 0,
        "Rules with Issues": 0,
        "Rules without Issues": 0,
    }
    summary["issues_by_group"] = defaultdict(int)
    summary["issues_by_type"] = defaultdict(lambda: defaultdict(int))

    rules: RULE_REPORTS_TYPE = output["rules"]  # type: ignore reportAssignmentType
    for rule in rules:
        issues: ISSUES_TYPE = rule["issues"]  # type: ignore reportAssignmentType
        summary["overall_summary"]["Total Issues"] += len(issues)

        if len(issues) == 0:
            summary["overall_summary"]["Rules without Issues"] += 1
        else:
            summary["overall_summary"]["Rules with Issues"] += 1

        checker_codes = defaultdict(lambda: defaultdict(int))
        for issue in issues:
            checker = issue["checker"]
            code = issue["code"]
            summary["issues_by_group"][checker] += 1
            checker_codes[checker][code] += 1

        for checker, codes in checker_codes.items():
            for code, count in codes.items():
                summary["issues_by_type"][checker][code] += count

    # Ensure also checkers and codes without issues are included in the report.
    for checker in get_checkers():
        if checker.__class__.__name__ not in summary["issues_by_group"]:
            summary["issues_by_group"][checker.__class__.__name__] = 0

        for code in checker.codes:
            if code not in summary["issues_by_type"][checker.__class__.__name__]:
                summary["issues_by_type"][checker.__class__.__name__][code] = 0

    # Sort dictionaries for deterministic output
    summary["issues_by_group"] = {
        key: summary["issues_by_group"][key]
        for key in sorted(summary["issues_by_group"].keys())
    }
    summary["issues_by_type"] = {
        key: {
            key2: summary["issues_by_type"][key][key2]
            for key2 in sorted(summary["issues_by_type"][key])
        }
        for key in sorted(summary["issues_by_type"].keys())
    }

    return summary


if __name__ == "__main__":
    main()
