"""`suricata_check` is a module and command line utility to provide feedback on Suricata rules."""

from suricata_check import checkers, tests, utils
from suricata_check._checkers import get_checkers
from suricata_check._suricata_check import (
    analyze_rule,
    get_ini_kwargs,
    main,
    process_rules_file,
)
from suricata_check._version import (
    __version__,
    check_for_update,
)

__all__ = (
    "__version__",
    "analyze_rule",
    "check_for_update",
    "checkers",
    "get_checkers",
    "get_ini_kwargs",
    "main",
    "process_rules_file",
    "tests",
    "utils",
)
