# noqa: D100
from typing import Mapping, Sequence

import idstools.rule

from ...utils import (
    HEADER_REGEX,
    get_regex_provider,
    is_rule_option_equal_to_regex,
)
from ..interface import CheckerInterface

REGEX_PROVIDER = get_regex_provider()

# Regular expressions are placed here such that they are compiled only once.
# This has a significant impact on the performance.
REGEX_S100 = REGEX_PROVIDER.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\( .*\)\s*(#.*)?$",
)
REGEX_S101 = REGEX_PROVIDER.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.* \)\s*(#.*)?$",
)
REGEX_S102 = REGEX_PROVIDER.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+ :.+\)\s*(#.*)?$",
)
REGEX_S103 = REGEX_PROVIDER.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+: .+\)\s*(#.*)?$",
)
REGEX_S104 = REGEX_PROVIDER.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+ ;.+\)\s*(#.*)?$",
)
REGEX_S105 = REGEX_PROVIDER.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+; \s+.+\)\s*(#.*)?$",
)
REGEX_S106 = REGEX_PROVIDER.compile(r'^".*\|.*  .*\|.*"$')
REGEX_S110 = REGEX_PROVIDER.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+;(?! ).+\)\s*(#.*)?$",
)
REGEX_S111 = REGEX_PROVIDER.compile(r'^".*\|.*[a-fA-F0-9]{4}.*\|.*"$')
REGEX_S120 = REGEX_PROVIDER.compile(
    r'^".*[\x3a\x3b\x20\x22\x27\x7b\x5c\x2f\x60\x24\x28\x29]+.*"$',
)
REGEX_S121 = REGEX_PROVIDER.compile(
    r'^"/.*(\\?[\x20]+|\\[\x3a\x3b\x22\x27\x7b\x5c\x7c\x2f\x60\x24\x28\x29]+).*/[ism]*"$',
)
REGEX_S122 = REGEX_PROVIDER.compile(r'^".*\\.*"$')
REGEX_S123 = REGEX_PROVIDER.compile(r'^".*\\(?!x).*"$')


class WhitespaceChecker(CheckerInterface):
    """The `WhitespaceChecker` contains several checks based on the Suricata Style guide relating to formatting rules.

    Codes S100-S109 report on unneccessary whitespace that should be removed.
    Codes S110-S119 report on missing whitespace that should be added.
    Codes S120-S129 report on non-standard escaping of special characters.
    """

    codes = (
        "S100",
        "S101",
        "S102",
        "S103",
        "S104",
        "S105",
        "S106",
        "S110",
        "S111",
        "S120",
        "S121",
        "S122",
        "S123",
    )

    def check_rule(  # noqa: C901, PLR0912, D102
        self: "WhitespaceChecker",
        rule: idstools.rule.Rule,
    ) -> Sequence[Mapping]:
        issues = []

        if (
            REGEX_S100.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S100",
                    "message": """The rule contains unneccessary whitespace after opening the rule body with.
Consider removing the unneccessary whitespace.""",
                },
            )

        if (
            REGEX_S101.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S101",
                    "message": """The rule contains unneccessary whitespace before closing the rule body with.
Consider removing the unneccessary whitespace.""",
                },
            )

        if (
            REGEX_S102.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S102",
                    "message": """The rule contains unneccessary whitespace before the colon (:) after an option name.
Consider removing the unneccessary whitespace.""",
                },
            )

        if (
            REGEX_S103.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S103",
                    "message": """The rule contains unneccessary whitespace before the colon (:) after an option name.
Consider removing the unneccessary whitespace.""",
                },
            )

        if (
            REGEX_S104.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S104",
                    "message": """The rule contains unneccessary whitespace before the semicolon (;) after an option value.
Consider removing the unneccessary whitespace.""",
                },
            )

        if (
            REGEX_S105.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S105",
                    "message": """The rule contains more than one space between options after an option value.
Consider replacing the unneccessary whitespace by a single space.""",
                },
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            REGEX_S106,
        ):
            issues.append(
                {
                    "code": "S106",
                    "message": """The rule contains more than one space between bytes in content.
Consider replacing the unneccessary whitespace by a single space.""",
                },
            )

        if (
            REGEX_S110.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                {
                    "code": "S110",
                    "message": """The rule does not contain a space between the end of after an option value.
Consider adding a single space.""",
                },
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            REGEX_S111,
        ):
            issues.append(
                {
                    "code": "S111",
                    "message": """The rule contains more than no spaces between bytes in content.
Consider replacing adding a single space.""",
                },
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            REGEX_S120,
        ):
            issues.append(
                {
                    "code": "S120",
                    "message": """The rule did not escape \
(\\x3a\\x3b\\x20\\x22\\x27\\x7b\\x7c\\x5c\\x2f\\x60\\x24\\x28\\x29) in a content field.
Consider using hex encoding instead.""",
                },
            )

        if is_rule_option_equal_to_regex(
            rule,
            "pcre",
            REGEX_S121,
        ):
            issues.append(
                {
                    "code": "S121",
                    "message": """The rule did escape \
(\\x3a\\x3b\\x20\\x22\\x27\\x7b\\x7c\\x5c\\x2f\\x60\\x24\\x28\\x29) in a pcre field.
Consider using hex encoding instead.""",
                },
            )

        if is_rule_option_equal_to_regex(rule, "content", REGEX_S122):
            issues.append(
                {
                    "code": "S122",
                    "message": """The rule escaped special characters in content using a blackslash (\\) in a content field.
Consider using hex encoding instead.""",
                },
            )

        if is_rule_option_equal_to_regex(rule, "pcre", REGEX_S123):
            issues.append(
                {
                    "code": "S123",
                    "message": """The rule escaped special characters in content using a blackslash (\\) in a pcre field.
Consider using hex encoding instead.""",
                },
            )

        return self._add_checker_metadata(issues)
