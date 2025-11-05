"""`suricata_check` is a module and command line utility to provide feedback on Suricata rules."""

from suricata_check import checkers, rule, tests, utils
from suricata_check._checkers import get_checkers
from suricata_check._version import (
    SURICATA_CHECK_DIR,
    __version__,
    check_for_update,
    get_dependency_versions,
)
from suricata_check.suricata_check import (
    analyze_rule,
    get_ini_kwargs,
    main,
    process_rules_file,
)

__all__ = (
    "SURICATA_CHECK_DIR",
    "__version__",
    "analyze_rule",
    "check_for_update",
    "checkers",
    "get_checkers",
    "get_dependency_versions",
    "get_ini_kwargs",
    "main",
    "process_rules_file",
    "rule",
    "tests",
    "utils",
)
