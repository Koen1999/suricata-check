"""`suricata_check` is a module and command line utility to provide feedback on Suricata rules."""

from suricata_check import checkers, tests, utils
from suricata_check._version import (
    SURICATA_CHECK_DIR,
    __version__,
    get_dependency_versions,
)
from suricata_check.suricata_check import (
    analyze_rule,
    get_checkers,
    main,
    process_rules_file,
)

__all__ = (
    "SURICATA_CHECK_DIR",
    "__version__",
    "analyze_rule",
    "checkers",
    "get_checkers",
    "get_dependency_versions",
    "main",
    "process_rules_file",
    "tests",
    "utils",
)
