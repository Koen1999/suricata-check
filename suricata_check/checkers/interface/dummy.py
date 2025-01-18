"""DummyChecker."""

import logging
from collections.abc import Iterable
from typing import Optional

from suricata_check.checkers.interface.checker import CheckerInterface

_logger = logging.getLogger(__name__)


class DummyChecker(CheckerInterface):
    """Dummy class to prevent runtime errors on import."""

    codes = {}
    enabled_by_default = False

    def __init__(self: "DummyChecker", include: Optional[Iterable[str]] = None) -> None:
        """Log an error due to failed imports for the checker."""
        _logger.warning(
            "Failed to initialize %s due to failed imports. Ensure all necessary dependencies are installed.",
            self.__class__.__name__,
        )
        super().__init__(include=include)
