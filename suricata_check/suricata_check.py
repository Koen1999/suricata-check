"""The `suricata_check.suricata_check` module contains the command line utility and the main program logic."""

import io
import logging
import os
import sys
from collections import defaultdict
from typing import Iterable, Literal, Mapping, MutableMapping, Optional, Sequence, Union

import click
import idstools.rule

from .checkers.interface import CheckerInterface
from .utils import check_rule_option_recognition, find_rules_file

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]

logger = logging.getLogger(__name__)

# TODO: Now
# - Implement a report that provides statistics over a rule given all issues for that rule.
# - Implement a report that provides statistics over an entire ruleset.
# - Implement checkers based on the Suricata Style Guide.
# - Implement checkers based on Ruling the Unruly.
# - Make it possible to only run checkers emitting certain codes through regular expression selection and an include exclude mechanism.
# - Some issues are irrelevant when other issues are present. I.e., whitespace in body is not relevant if sid is missing. Implement a way to filter out irrelevant issues.
# -

# TODO: Before publication
# - Better define how to contribute to this project by setting up CONTRIBUTING.md and providing issue templates
# - Make a wheel for PyPi
# - Investigate possibilities to allow for custom checkers through third party packages with similar interfaces.
# - Add some shields.io badges to the README.md
# - Profile the tool and make it faster (regular expression matches?)


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
            logging.StreamHandler(stream=sys.stdout),
        ),
    )

    # Log the arguments:
    logger.info("Running suricata-check with the following arguments:")
    logger.info("out: %s", out)
    logger.info("rules: %s", rules)
    logger.info("single_rule: %s", single_rule)
    logger.info("log_level: %s", log_level)
    logger.info("evaluate_disabled: %s", evaluate_disabled)

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

        _write_output([rule_dict], out)

        # Return here so no rules file is processed.
        return

    # Check if the rules argument is valid and find the rules file
    rules = find_rules_file(rules)

    output = process_rules_file(rules, evaluate_disabled, checkers=checkers)

    _write_output(output, out)


def _write_output(
    output: list[Mapping[str, Union[idstools.rule.Rule, list[Mapping], Mapping, int]]],
    out: str,
) -> None:
    logger.info(
        "Writing output to suricata-check.jsonl and suricata-check.fast in %s",
        os.path.abspath(out),
    )
    with (
        open(
            os.path.join(out, "suricata-check.jsonl"),
            "w",
            buffering=io.DEFAULT_BUFFER_SIZE,
        ) as jsonl_fh,
        open(
            os.path.join(out, "suricata-check.fast"),
            "w",
            buffering=io.DEFAULT_BUFFER_SIZE,
        ) as fast_fh,
    ):
        jsonl_fh.write("\n".join([str(rule) for rule in output]))

        for rule_dict in output:
            rule: idstools.rule.Rule = rule_dict["rule"]  # type: ignore reportAssignmentType
            line: Optional[int] = rule_dict["line"] if "line" in rule_dict else None  # type: ignore reportAssignmentType
            issues: list[Mapping] = rule_dict["issues"]  # type: ignore reportAssignmentType
            for issue in issues:
                code = issue["code"]
                issue_msg = issue["message"].replace("\n", " ")

                msg = f"[{code}] Line {line}, sid {rule['sid']}: {issue_msg}\n"
                fast_fh.write(msg)
                print(msg)  # noqa: T201


def process_rules_file(
    rules: str,
    evaluate_disabled: bool,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> list[Mapping[str, Union[idstools.rule.Rule, list[Mapping], Mapping, int]]]:
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

    output = []

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

            dict_out: MutableMapping[
                str,
                Union[idstools.rule.Rule, list[Mapping], Mapping, int],
            ] = analyze_rule(
                rule,
                checkers=checkers,
            )  # type: ignore reportAssignmentType
            dict_out["line"] = number
            output.append(dict_out)

    logger.info("Completed processing rule file: %s", rules)

    # TODO: Implement some sort of report that provides statistics over an entire ruleset.

    return output


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

    checkers = sorted(checkers, key=lambda x: x.__class__.__name__)

    return checkers


def analyze_rule(
    rule: idstools.rule.Rule,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> MutableMapping[str, Union[idstools.rule.Rule, list[Mapping], Mapping]]:
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

    dict_out: MutableMapping[str, Union[idstools.rule.Rule, list[Mapping], Mapping]] = {
        "rule": rule,
    }

    issues: list[Mapping] = []
    for checker in checkers:
        issues += checker.check_rule(rule)

    dict_out["issues"] = issues

    dict_out["summary"] = __summarize_rule(dict_out)

    return dict_out


def __summarize_rule(
    rule: MutableMapping[str, Union[idstools.rule.Rule, list[Mapping], Mapping]],
) -> MutableMapping:
    """Summarizes the issues found in a rule.

    Args:
    ----
    rule: The rule output dictionary to be summarized.

    Returns:
    -------
    A dictionary containing a summary of all issues found in the rule.

    """
    summary = {}

    summary["total_issues"] = len(rule["issues"])
    summary["issues_by_group"] = defaultdict(int)
    for issue in rule["issues"]:
        checker = issue["checker"]
        summary["issues_by_group"][checker] += 1

    return summary


if __name__ == "__main__":
    main()
