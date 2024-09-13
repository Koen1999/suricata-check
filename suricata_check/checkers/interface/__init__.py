"""The `suricata_check.checkers.interface` modules contains the interfaces implemented by checkers.

Implementation of the `CheckerInterface` is neccessary for checker auto-discovery.
"""

from suricata_check.checkers.interface.checker import CheckerInterface
from suricata_check.checkers.interface.dummy import DummyChecker

__all__ = ["CheckerInterface", "DummyChecker"]
