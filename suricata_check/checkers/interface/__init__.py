"""The `suricata_check.checkers.interface` modules contains the interfaces implemented by checkers.

Implementation of the ``suricata_check.checkers.interface.CheckerInterface`` is neccessary for checker auto-discovery.
"""

from suricata_check.checkers.interface._checker import CheckerInterface
from suricata_check.checkers.interface._dummy import DummyChecker

__all__ = ["CheckerInterface", "DummyChecker"]
