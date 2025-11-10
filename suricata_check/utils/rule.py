"""Module replacing idstools.rule and providing limited but similar functionality.

This module is inspired by and mostly uses the same interface Python idstools package. (https://github.com/jasonish/py-idstools)
"""

import inspect
from collections.abc import Hashable, Sequence
from dataclasses import dataclass
from typing import Optional

from suricata_check.utils.regex_provider import get_regex_provider

_regex_provider = get_regex_provider()

RULE_PATTERN = _regex_provider.compile(
    r"^(?P<enabled>#)*[\s#]*(?P<raw>(?P<header>[^()]+)\((?P<options>.*)\)$)"
)

RULE_ACTIONS = (
    "alert",
    "config",
    "log",
    "pass",
    "activate",
    "dynamic",
    "drop",
    "reject",
    "sdrop",
)


@dataclass
class RuleOption:
    """Class representing a rule option."""

    name: str
    value: Optional[str] = None

    def _to_dict(self: "RuleOption") -> dict[str, Hashable]:
        """Returns the RuleOption represented as a dictionary."""
        return {
            "name": self.name,
            "value": self.value,
        }

    def __hash__(self) -> int:
        """Returns a unique hash that can be used as a fingerprint for the rule option."""
        return hash(tuple(sorted(self._to_dict().items())))


@dataclass
class Rule:
    """Class representing a rule."""

    raw: str
    header: str
    enabled: bool
    action: str
    proto: str
    source_addr: str
    source_port: str
    direction: str
    dest_addr: str
    dest_port: str
    options: tuple[RuleOption, ...] = ()
    metadata: tuple[str, ...] = ()
    flowbits: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def __init__(self, *args: tuple, **kwargs: dict) -> None:
        """Private Init function.

        Use suricata_check.utils.rule.parse() instead to create Rule instances.
        """
        if inspect.stack()[1].function != "parse":
            raise RuntimeError(
                "Rule instances must be created using suricata_check.utils.rule.parse()"
            )
        super().__init__(*args, **kwargs)

    def add_option(self, name: str, value: Optional[str]) -> None:
        """Adds an option in the rule's options list."""
        if not isinstance(name, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Option name must be a string")
        if value is not None and not isinstance(
            value, str
        ):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Option value must be a string")

        self.options = (*self.options, RuleOption(name=name, value=value))

    def add_metadata_options(self, values: Sequence[str]) -> None:
        """Adds metadata options in the rule's metadata list."""
        for value in values:
            if not isinstance(
                value, str
            ):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise TypeError("Metadata option value must be a string")
        self.metadata = (*self.metadata, *values)

    def add_flowbits_option(self, value: str) -> None:
        """Adds a flowbits option in the rule's flowbits list."""
        if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Flowbits option value must be a string")
        self.flowbits = (*self.flowbits, value)

    def add_reference_option(self, value: str) -> None:
        """Adds a reference option in the rule's references list."""
        if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError("Reference option value must be a string")
        self.references = (*self.references, value)

    def _to_dict(self: "Rule") -> dict[str, Hashable]:
        """Returns the Rule represented as a dictionary."""
        return {
            "raw": self.raw,
            "header": self.header,
            "enabled": self.enabled,
            "action": self.action,
            "proto": self.proto,
            "source_addr": self.source_addr,
            "source_port": self.source_port,
            "direction": self.direction,
            "dest_addr": self.dest_addr,
            "dest_port": self.dest_port,
            "options": self.options,
            "metadata": self.metadata,
            "flowbits": self.flowbits,
        }

    def __hash__(self) -> int:
        """Returns a unique hash that can be used as a fingerprint for the rule."""
        return hash(tuple(sorted(self._to_dict().items())))


class ParsingError(RuntimeError):
    """Raised when a rule cannot be parsed by suricata-check.

    Most likely, such a rule is also an invalid Suricata rule.
    """

    def __init__(self: "ParsingError", message: str) -> None:
        """Initializes the `ParsingError` with the raw rule as message."""
        super().__init__(message)


def parse(buffer: str) -> Optional["Rule"]:
    """Parse a rule stringand return a wrapped `Rule` instance.

    Returns None when the text could not be parsed as a rule.

    :param buffer: A string containing a single Suricata-like rule

    :returns: An instance of of `Rule` representing the parsed rule
    """
    text = buffer.strip()

    m = RULE_PATTERN.match(text)
    if not m:
        return None

    rule = Rule()
    rule.raw = m.group("raw").strip()
    rule.header = m.group("header").strip()

    if m.group("enabled") == "#":
        rule.enabled = False
    else:
        rule.enabled = True

    header_vals = _regex_provider.split(r"\s+", rule.header)
    # 7 is the number of expected header fields
    if len(header_vals) != 7:  # noqa: PLR2004
        return None
    (
        rule.action,
        rule.proto,
        rule.source_addr,
        rule.source_port,
        rule.direction,
        rule.dest_addr,
        rule.dest_port,
    ) = header_vals

    if rule.action not in RULE_ACTIONS:
        return None

    options = m.group("options")

    __add_options_to_rule(text, rule, options)

    return rule


def __add_options_to_rule(rule_text: str, rule: "Rule", options: str) -> None:
    while True:
        if not options:
            break
        index = __find_opt_end(options)
        if index < 0:
            raise ParsingError("end of option not found: {}".format(rule_text))
        option = options[:index].strip()
        options = options[index + 1 :].strip()

        if option.find(":") > -1:
            name, val = [x.strip() for x in option.split(":", 1)]
        else:
            name = option
            val = None

        __add_option_to_rule(rule, name, val)


def __add_option_to_rule(  # noqa: C901, PLR0912
    rule: "Rule", name: str, val: Optional[str]
) -> None:
    if val is not None and not isinstance(
        val, str
    ):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ParsingError(f"Invalid option value type ({type(val)}): {val}")
    rule.add_option(name, val)

    if name in ["gid", "sid", "rev"]:
        try:
            setattr(rule, name, int(val))  # pyright: ignore[reportArgumentType]
        except ValueError:
            raise ParsingError(f"Failed to convert {name} value to int: {val}")
    elif name == "metadata":
        if not isinstance(val, str):
            raise ParsingError(f"Invalid metadata value type ({type(val)}): {val}")
        rule.add_metadata_options([v.strip() for v in val.split(",")])
    elif name == "flowbits":
        if not isinstance(val, str):
            raise ParsingError(f"Invalid flowbits value type ({type(val)}): {val}")
        rule.add_flowbits_option(val)
    elif name == "reference":
        if not isinstance(val, str):
            raise ParsingError(f"Invalid reference value type ({type(val)}): {val}")
        rule.add_reference_option(val)
    elif name == "msg":
        if not isinstance(val, str):
            raise ParsingError(f"Invalid msg value type ({type(val)}): {val}")
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        setattr(rule, name, val)
    else:
        setattr(rule, name, val)


def __find_opt_end(options: str) -> int:
    """Find the end of an option (;) handling escapes."""
    offset = 0

    while True:
        i = options[offset:].find(";")
        if options[offset + i - 1] == "\\":
            offset += 2
        else:
            return offset + i
