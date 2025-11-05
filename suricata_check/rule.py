"""Wrapper around idstools.rule.Rule for future removal of idstools dependency."""

from typing import Optional

import idstools.rule


class Rule:
    """Wrapper around an `suricata_check.rule.Rule` in preparation for dropping the idstools dependency."""

    def __init__(self, inner: Optional[idstools.rule.Rule]) -> None:
        """Create a wrapper around an existing `suricata_check.rule.Rule`.

        Parameters
        ----------
        inner:
            The parsed rule object from `suricata_check.rule.parse()` or None.
        """
        super().__init__()
        self._inner = inner

    @property
    def inner(self) -> Optional[idstools.rule.Rule]:
        """Return the underlying parsed rule object (or None)."""
        return self._inner

    def __getitem__(self, key: str):  # noqa: ANN204
        """Forward mapping access to the underlying rule.

        Raises KeyError when no underlying rule is present.
        """
        if self._inner is None:
            raise KeyError(key)
        return self._inner[key]

    def get(self, key: str, default: Optional[object] = None):  # noqa: ANN201
        """Return the value for *key* if present, otherwise *default*."""
        if self._inner is None:
            return default
        return self._inner.get(key, default)

    def __contains__(self, key: str) -> bool:
        """Return True when the underlying rule contains *key*."""
        return self._inner is not None and key in self._inner

    def __repr__(self) -> str:
        """Return representation of the wrapped rule (or 'None')."""
        return repr(self._inner)


class ParsingError(RuntimeError):
    """Raised when a rule cannot be parsed by suricata-check.

    Most likely, such a rule is also an invalid Suricata rule.
    """

    def __init__(self: "ParsingError", message: str) -> None:
        """Initializes the `ParsingError` with the raw rule as message."""
        super().__init__(message)


def parse(text: Optional[str]) -> Optional["Rule"]:
    """Parse a rule string using the underlying `idstools` parser.

    Return a wrapped `Rule` instance.

    Returns None when the text could not be parsed as a rule.
    """
    try:
        inner = idstools.rule.parse(text)
    except Exception as e:  # noqa: BLE001
        raise ParsingError(str(e))

    if inner is None:
        return None

    return Rule(inner)
