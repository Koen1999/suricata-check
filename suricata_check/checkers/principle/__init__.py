"""The `suricata_check.checkers.principle` modules contains several checkers based on the Ruling the Unruly paper.

Reference: TODO
"""

from suricata_check.checkers.interface.dummy import DummyChecker
from suricata_check.checkers.principle.principle import PrincipleChecker

try:
    from suricata_check.checkers.principle.ml import PrincipleMLChecker  # type: ignore reportAssignmentType
except ImportError:

    class PrincipleMLChecker(DummyChecker):
        """Dummy class to prevent runtime errors on import."""


__all__ = [
    "PrincipleChecker",
    "PrincipleMLChecker",
]
