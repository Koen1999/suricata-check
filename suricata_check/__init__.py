"""`suricata_check` is a module and command line utility to provide feedback on Suricata rules."""

from suricata_check import checkers, utils
from suricata_check.suricata_check import (
    __version__,
    analyze_rule,
    get_checkers,
    main,
    process_rules_file,
)
