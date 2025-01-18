"""`WhitespaceChecker`."""

import logging

import idstools.rule

from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.checker import (
    is_rule_option_equal_to_regex,
)
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue
from suricata_check.utils.regex import (
    HEADER_REGEX,
    get_regex_provider,
)

_regex_provider = get_regex_provider()

# Regular expressions are placed here such that they are compiled only once.
# This has a significant impact on the performance.
REGEX_S100 = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\( .*\)\s*(#.*)?$",
)
REGEX_S101 = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.* \)\s*(#.*)?$",
)
REGEX_S102 = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+ :.+\)\s*(#.*)?$",
)
REGEX_S103 = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+: .+\)\s*(#.*)?$",
)
REGEX_S104 = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+ ;.+\)\s*(#.*)?$",
)
REGEX_S105 = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+; \s+.+\)\s*(#.*)?$",
)
REGEX_S106 = _regex_provider.compile(r'^".*\|.*  .*\|.*"$')
REGEX_S110 = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*\(.+;(?! ).+\)\s*(#.*)?$",
)
REGEX_S111 = _regex_provider.compile(r'^".*\|.*[a-fA-F0-9]{4}.*\|.*"$')
REGEX_S120 = _regex_provider.compile(
    r'^"([^\|]*|(\|[\sa-zA-Z0-9]*\|))*(\\?[\x3a\x3b\x20\x27\x7b\x5c\x2f\x60\x24\x28\x29]+|\\[\x22\x7c]+)([^\|]*|(\|[\sa-zA-Z0-9]*\|))*"$',
)
REGEX_S121 = _regex_provider.compile(
    r"^\"/.*(\\?[\x3a\x3b\x20\x22\x27\x2f\x60]+|\\[\x7b\x5c\x7c\x24\x28\x29]+).*/[ism]*\"$",
)
REGEX_S122 = _regex_provider.compile(r'^".*\\.*"$')
REGEX_S123 = _regex_provider.compile(
    r'^".*(?!\\(a|c[0-127]|e|f|n|r|t|0[0-9]{2}|[0-9]{3}|0\{[0-9]{3}\}|x[0-9a-f]{2}|x[0-9a-f]{3}|u[0-9a-f]{4}|d|D|h|H|s|S|v|V|w|W))(\\.).*"$'
)


class WhitespaceChecker(CheckerInterface):
    """The `WhitespaceChecker` contains several checks based on the Suricata Style guide relating to formatting rules.

    Codes S100-S109 report on unneccessary whitespace that should be removed.

    Codes S110-S119 report on missing whitespace that should be added.

    Codes S120-S129 report on non-standard escaping of special characters.
    """

    codes = {
        "S100": {"severity": logging.INFO},
        "S101": {"severity": logging.INFO},
        "S102": {"severity": logging.INFO},
        "S103": {"severity": logging.INFO},
        "S104": {"severity": logging.INFO},
        "S105": {"severity": logging.INFO},
        "S106": {"severity": logging.INFO},
        "S110": {"severity": logging.INFO},
        "S111": {"severity": logging.INFO},
        "S120": {"severity": logging.INFO},
        "S121": {"severity": logging.INFO},
        "S122": {"severity": logging.INFO},
        "S123": {"severity": logging.INFO},
    }

    def _check_rule(  # noqa: C901, PLR0912
        self: "WhitespaceChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if (
            REGEX_S100.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S100",
                    message="""The rule contains unneccessary whitespace after opening the rule body with.
Consider removing the unneccessary whitespace.""",
                ),
            )

        if (
            REGEX_S101.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S101",
                    message="""The rule contains unneccessary whitespace before closing the rule body with.
Consider removing the unneccessary whitespace.""",
                ),
            )

        if (
            REGEX_S102.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S102",
                    message="""The rule contains unneccessary whitespace before the colon (:) after an option name.
Consider removing the unneccessary whitespace.""",
                ),
            )

        if (
            REGEX_S103.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S103",
                    message="""The rule contains unneccessary whitespace before the colon (:) after an option name.
Consider removing the unneccessary whitespace.""",
                ),
            )

        if (
            REGEX_S104.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S104",
                    message="""The rule contains unneccessary whitespace before the semicolon (;) after an option value.
Consider removing the unneccessary whitespace.""",
                ),
            )

        if (
            REGEX_S105.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S105",
                    message="""The rule contains more than one space between options after an option value.
Consider replacing the unneccessary whitespace by a single space.""",
                ),
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            REGEX_S106,
        ):
            issues.append(
                Issue(
                    code="S106",
                    message="""The rule contains more than one space between bytes in content.
Consider replacing the unneccessary whitespace by a single space.""",
                ),
            )

        if (
            REGEX_S110.match(
                rule["raw"].strip(),
            )
            is not None
        ):
            issues.append(
                Issue(
                    code="S110",
                    message="""The rule does not contain a space between the end of after an option value.
Consider adding a single space.""",
                ),
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            REGEX_S111,
        ):
            issues.append(
                Issue(
                    code="S111",
                    message="""The rule contains more than no spaces between bytes in content.
Consider replacing adding a single space.""",
                ),
            )

        if is_rule_option_equal_to_regex(
            rule,
            "content",
            REGEX_S120,
        ):
            issues.append(
                Issue(
                    code="S120",
                    message="""The rule did not escape \
(\\x3a\\x3b\\x20\\x22\\x27\\x7b\\x7c\\x5c\\x2f\\x60\\x24\\x28\\x29) in a content field.
Consider using hex encoding instead.""",
                ),
            )

        if is_rule_option_equal_to_regex(
            rule,
            "pcre",
            REGEX_S121,
        ):
            issues.append(
                Issue(
                    code="S121",
                    message="""The rule did escape \
(\\x3a\\x3b\\x20\\x22\\x27\\x7b\\x7c\\x5c\\x2f\\x60\\x24\\x28\\x29) in a pcre field.
Consider using hex encoding instead.""",
                ),
            )

        if is_rule_option_equal_to_regex(rule, "content", REGEX_S122):
            issues.append(
                Issue(
                    code="S122",
                    message="""The rule escaped special characters using a blackslash (\\) in a content field.
Consider using hex encoding instead.""",
                ),
            )

        if is_rule_option_equal_to_regex(rule, "pcre", REGEX_S123):
            issues.append(
                Issue(
                    code="S123",
                    message="""The rule escaped special characters using a blackslash (\\) in a pcre field.
Consider using hex encoding instead.""",
                ),
            )

        return issues
