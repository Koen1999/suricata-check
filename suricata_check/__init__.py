"""`suricata_check` is a module and command line utility to provide feedback on Suricata rules."""

from suricata_check import checkers, utils
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
    "checkers",
    "utils",
    "SURICATA_CHECK_DIR",
    "__version__",
    "get_dependency_versions",
    "analyze_rule",
    "get_checkers",
    "main",
    "process_rules_file",
)
