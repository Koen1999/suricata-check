import io
import json
import logging
import os
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Optional, Union

import click
import tabulate

from suricata_check._checkers import get_checkers
from suricata_check.checkers.interface.checker import CheckerInterface
from suricata_check.utils.checker_typing import (
    EXTENSIVE_SUMMARY_TYPE,
    ISSUES_TYPE,
    RULE_REPORTS_TYPE,
    RULE_SUMMARY_TYPE,
    SIMPLE_SUMMARY_TYPE,
    OutputReport,
    OutputSummary,
    Rule,
    RuleReport,
)

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


def write_output(
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
            rule: Rule = rule_report.rule
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


def summarize_rule(
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


def summarize_output(
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
