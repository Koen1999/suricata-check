# noqa: D100
from typing import Mapping, Sequence

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils import is_rule_option_set


class MandatoryChecker(CheckerInterface):
    """The `MandatoryChecker` contains several checks based on the Suricata syntax that are critical.

    Codes M000-M009 report on missing mandatory rule options.
    """

    codes = (
        "M000",
        "M001",
    )

    def check_rule(  # noqa: D102
        self: "MandatoryChecker",
        rule: idstools.rule.Rule,
    ) -> Sequence[Mapping]:
        issues = []

        if not is_rule_option_set(rule, "msg"):
            issues.append(
                {
                    "code": "M000",
                    "message": "The rule did not specify a msg, which is a mandatory field.",
                },
            )

        if not is_rule_option_set(rule, "sid"):
            issues.append(
                {
                    "code": "M001",
                    "message": "The rule did not specify a sid, which is a mandatory field.",
                },
            )

        return self._add_checker_metadata(issues)
