"""The `suricata_check.typing` module contains all types used by the `suricata-check` package."""

from collections.abc import MutableMapping, MutableSequence
from typing import (
    Union,
)

import idstools.rule

ISSUE_TYPE = MutableMapping[str, str]
ISSUES_TYPE = MutableSequence[ISSUE_TYPE]
SIMPLE_SUMMARY_TYPE = MutableMapping[str, int]
RULE_SUMMARY_TYPE = SIMPLE_SUMMARY_TYPE
EXTENSIVE_SUMMARY_TYPE = MutableMapping[str, SIMPLE_SUMMARY_TYPE]
RULE_REPORT_TYPE = MutableMapping[
    str,
    Union[idstools.rule.Rule, ISSUES_TYPE, RULE_SUMMARY_TYPE, int],
]
RULE_REPORTS_TYPE = MutableSequence[RULE_REPORT_TYPE]
OUTPUT_SUMMARY_TYPE = MutableMapping[
    str,
    Union[SIMPLE_SUMMARY_TYPE, EXTENSIVE_SUMMARY_TYPE],
]
OUTPUT_REPORT_TYPE = MutableMapping[
    str,
    Union[
        RULE_REPORTS_TYPE,
        OUTPUT_SUMMARY_TYPE,
    ],
]
