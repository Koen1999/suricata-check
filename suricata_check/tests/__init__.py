"""The `suricata_check.checkers` module contains all rule checkers."""

# Exception may occur if pytest is not installed.
try:
    from suricata_check.tests.checker import GenericChecker

    __all__ = [
        "GenericChecker",
    ]
except ModuleNotFoundError:
    import sys as _sys

    # Only warn about failed import if not used as CLI.
    if not _sys.argv[0].endswith("suricata_check.py"):
        import logging as _logging

        _logger = _logging.getLogger(__name__)
        _logger.warning(
            """Failed to initialize `suricata_check.tests.checker.GenericChecker` due to failed imports. \
    Ensure all necessary development dependencies are installed if you need to run tests.""",
        )
    __all__ = []
