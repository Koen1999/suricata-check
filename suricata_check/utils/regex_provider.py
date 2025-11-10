"""The `suricata_check.utils.regex_provider` module provides a unified interface for regex operations."""

import importlib.util
import logging
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    import re

    import regex

_logger = logging.getLogger(__name__)

# Import the fastest regex provider available:
if importlib.util.find_spec("regex") is not None:
    _logger.info("Detected regex module as installed, using it.")
    import regex as _regex_provider
else:
    _logger.warning(
        """Did not detect regex module as installed, using re instead.
To increase suricata-check processing speed, consider isntalling the regex module \
by running `pip install suricata-check[performance]`.""",
    )
    import re as _regex_provider


def get_regex_provider():  # noqa: ANN201
    """Returns the regex provider to be used.

    If `regex` is installed, it will return that module.
    Otherwise, it will return the `re` module instead.
    """
    return _regex_provider


Pattern = Union["re.Pattern", "regex.Pattern"]
Match = Union["re.Match", "regex.Match"]
