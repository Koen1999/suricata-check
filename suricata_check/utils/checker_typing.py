"""The `suricata_check.typing` module contains all types used by the `suricata-check` package."""

import json
from collections.abc import Iterable, MutableMapping, MutableSequence
from dataclasses import dataclass, field
from typing import (
    Optional,
    TypeVar,
)

import idstools.rule


class InvalidRuleError(RuntimeError):
    """Raised when an invalid rule is detected.

    Note that some rules may be invalid due to not following the Suricata rule syntax.
    Rules following the syntax, but considered invalid by Suricata due to missing options need not raise this error.
    Rules for which this error is not raised are not neccessarily syntactically correct but can be processed by suricata-check.
    """

    def __init__(self: "InvalidRuleError", message: str) -> None:
        """Initializes the `InvalidRuleError` with the raw rule as message."""
        super().__init__(message)


@dataclass
class Issue:
    """The `Issue` dataclass represents a single issue found in a rule."""

    code: str
    message: str
    severity: Optional[int] = None
    checker: Optional[str] = None

    def to_dict(self: "Issue") -> dict[str, str]:
        """Returns the Issue represented as a dictionary."""
        d = {
            "code": self.code,
            "message": self.message,
        }

        if self.checker is not None:
            d["checker"] = self.checker

        return d

    @property
    def hash(self: "Issue") -> int:
        """Returns a unique hash that can be used as a fingerprint for the issue."""
        return hash(tuple(sorted(self.to_dict().items())))

    def __repr__(self: "Issue") -> str:
        """Returns the Issue represented as a string."""
        return json.dumps(self.to_dict())


ISSUES_TYPE = MutableSequence[Issue]
SIMPLE_SUMMARY_TYPE = MutableMapping[str, int]
RULE_SUMMARY_TYPE = SIMPLE_SUMMARY_TYPE
EXTENSIVE_SUMMARY_TYPE = MutableMapping[str, SIMPLE_SUMMARY_TYPE]

Cls = TypeVar("Cls")


def get_all_subclasses(cls: type[Cls]) -> Iterable[type[Cls]]:
    """Returns all class types that subclass the provided type."""
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses


@dataclass
class RuleReport:
    """The `RuleReport` dataclass represents a rule, together with information on its location and detected issues."""

    rule: idstools.rule.Rule
    summary: Optional[RULE_SUMMARY_TYPE] = None
    line_begin: Optional[int] = None
    line_end: Optional[int] = None

    _issues: ISSUES_TYPE = field(default_factory=list, init=False)

    @property
    def issues(self: "RuleReport") -> ISSUES_TYPE:
        """List of issues found in the rule."""
        return self._issues

    def add_issue(self: "RuleReport", issue: Issue) -> None:
        """Adds an issue to the report."""
        self._issues.append(issue)

    def add_issues(self: "RuleReport", issues: ISSUES_TYPE) -> None:
        """Adds an issue to the report."""
        for issue in issues:
            self._issues.append(issue)

    def to_dict(self: "RuleReport") -> dict[str, str]:
        """Returns the RuleReport represented as a dictionary."""
        d = {
            "rule": self.rule["raw"],
            "issues": [issue.to_dict() for issue in self.issues],
        }

        if self.summary is not None:
            d["summary"] = self.summary

        if self.line_begin is not None or self.line_end is not None:
            d["lines"] = {}

        if self.line_begin is not None:
            d["lines"]["begin"] = self.line_begin

        if self.line_begin is not None:
            d["lines"]["end"] = self.line_end

        return d

    def __repr__(self: "RuleReport") -> str:
        """Returns the RuleReport represented as a string."""
        return json.dumps(self.to_dict())


RULE_REPORTS_TYPE = MutableSequence[RuleReport]


@dataclass
class OutputSummary:
    """The `OutputSummary` dataclass represent a collection of summaries on the output of `suricata_check`."""

    overall_summary: SIMPLE_SUMMARY_TYPE
    issues_by_group: SIMPLE_SUMMARY_TYPE
    issues_by_type: EXTENSIVE_SUMMARY_TYPE


@dataclass
class OutputReport:
    """The `OutputSummary` dataclass represent the `suricata_check`, consisting of rule reports and summaries."""

    _rules: RULE_REPORTS_TYPE = field(default_factory=list, init=False)
    summary: Optional[OutputSummary] = None

    def __init__(
        self: "OutputReport",
        rules: RULE_REPORTS_TYPE = [],
        summary: Optional[OutputSummary] = None,
    ) -> None:
        """Initialized the `OutputReport`, optionally with a list of rules and/or a summary."""
        self._rules = []
        for rule in rules:
            self.add_rule(rule)
        self.summary = summary
        super().__init__()

    @property
    def rules(self: "OutputReport") -> RULE_REPORTS_TYPE:
        """List of rules contained in the report."""
        return self._rules

    def add_rule(self: "OutputReport", rule_report: RuleReport) -> None:
        """Adds an rule to the report."""
        self._rules.append(rule_report)
