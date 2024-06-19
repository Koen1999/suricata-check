"""The `suricata_check.utils.checker` module contains several utilities for developing rule checkers."""

import logging
from functools import lru_cache
from typing import Container, Iterable, Optional, Sequence, Sized, Union

import idstools.rule

from .regex import (
    ALL_METADATA_OPTIONS,
    ALL_OPTIONS,
    STICKY_BUFFER_NAMING,
    get_variable_groups,
    regex_provider,
)

LRU_CACHE_SIZE = 10


logger = logging.getLogger(__name__)


def check_rule_option_recognition(rule: idstools.rule.Rule) -> None:
    """Checks whether all rule options and metadata options are recognized.

    Unrecognized options will be logged as a warning in `suricata-check.log`
    """
    for option in rule["options"]:
        name = option["name"]
        if name not in ALL_OPTIONS:
            logger.warning(
                "Option %s from rule %i is not recognized.",
                name,
                rule["sid"],
            )

    for option in rule["metadata"]:
        name = regex_provider.split(r"\s+", option)[0]
        if name not in ALL_METADATA_OPTIONS:
            logger.warning(
                "Metadata option %s from rule %i is not recognized.",
                name,
                rule["sid"],
            )


@lru_cache(maxsize=LRU_CACHE_SIZE)
def is_rule_option_set(rule: idstools.rule.Rule, name: str) -> bool:
    """Checks whether a rule has a certain option set.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option

    Returns:
    -------
        bool: True iff the option is set atleast once

    """
    if name not in (
        "action",
        "proto",
        "source_addr",
        "source_port",
        "direction",
        "dest_addr",
        "dest_port",
    ):
        for option in rule["options"]:
            if option["name"] == name:
                return True

        return False

    if name not in rule:
        return False

    if rule[name] is None:
        return False

    if rule[name] == "":
        return False

    return True


def count_rule_options(
    rule: idstools.rule.Rule,
    name: Union[str, Iterable[str]],
) -> int:
    """Counts how often an option is set in a rule.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        name (Union[str, Iterable[str]]): name or names of the option

    Returns:
    -------
        int: The number of times an option is set

    """
    if not isinstance(name, str):
        name = tuple(sorted(name))
    return _count_rule_options(rule, name)


@lru_cache(maxsize=LRU_CACHE_SIZE)
def _count_rule_options(
    rule: idstools.rule.Rule,
    name: Union[str, Iterable[str]],
) -> int:
    count = 0

    if not isinstance(name, str):
        for single_name in name:
            count += count_rule_options(rule, single_name)
        return count

    if name not in (
        "action",
        "proto",
        "source_addr",
        "source_port",
        "direction",
        "dest_addr",
        "dest_port",
    ):
        for option in rule["options"]:
            if option["name"] == name:
                count += 1

    if is_rule_option_set(rule, name):
        count = max(count, 1)

    return count


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_rule_option(rule: idstools.rule.Rule, name: str) -> Optional[str]:
    """Retrieves one option of a rule with a certain name.

    If an option is set multiple times, it returns only one indeterminately.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option

    Returns:
    -------
        Optional[str]: The value of the option or None if it was not set.

    """
    if name not in (
        "action",
        "proto",
        "source_addr",
        "source_port",
        "direction",
        "dest_addr",
        "dest_port",
    ):
        for option in rule["options"]:
            if option["name"] == name:
                return option["value"]

    if name in rule:
        return rule[name]

    msg = f"Option {name} not found in rule {rule}."
    logger.debug(msg)

    return None


def get_rule_options(
    rule: idstools.rule.Rule,
    name: Union[str, Iterable[str]],
) -> Sequence[str]:
    """Retrieves all options of a rule with a certain name.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        name (Union[str, Iterable[str]]): name or names of the option

    Returns:
    -------
        Sequence[str]: The values of the option.

    """
    if not isinstance(name, str):
        name = tuple(sorted(name))
    return _get_rule_options(rule, name)


@lru_cache(maxsize=LRU_CACHE_SIZE)
def _get_rule_options(
    rule: idstools.rule.Rule,
    name: Union[str, Iterable[str]],
) -> Sequence[str]:
    values = []

    if not isinstance(name, str):
        for single_name in name:
            values.extend(_get_rule_options(rule, single_name))
        return values

    if name not in (
        "action",
        "proto",
        "source_addr",
        "source_port",
        "direction",
        "dest_addr",
        "dest_port",
    ):
        for option in rule["options"]:
            if option["name"] == name:
                values.append(option["value"])
    elif name in rule:
        values.append(rule[name])

    if len(values) == 0:
        msg = f"Option {name} not found in rule {rule}."
        logger.debug(msg)

    return values


def is_rule_option_equal_to(rule: idstools.rule.Rule, name: str, value: str) -> bool:
    """Checks whether a rule has a certain option set to a certain value.

    If the option is set multiple times, it will return True if atleast one option matches the value.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        value (str): value to check for

    Returns:
    -------
        bool: True iff the rule has the option set to the value atleast once

    """
    if not is_rule_option_set(rule, name):
        return False

    if get_rule_option(rule, name) == value:
        return True

    return False


def is_rule_option_equal_to_regex(
    rule: idstools.rule.Rule,
    name: str,
    regex,  # re.Pattern or regex.Pattern  # noqa: ANN001
) -> bool:
    """Checks whether a rule has a certain option set to match a certain regex.

    If the option is set multiple times, it will return True if atleast one option matches the regex.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        regex (Union[re.Pattern, regex.Pattern]): regex to check for

    Returns:
    -------
        bool: True iff the rule has atleast one option matching the regex

    """
    if not is_rule_option_set(rule, name):
        return False

    values = get_rule_options(rule, name)

    for value in values:
        if regex.match(value) is not None:
            return True

    return False


def are_rule_options_equal_to_regex(
    rule: idstools.rule.Rule,
    names: Iterable[str],
    regex,  # re.Pattern or regex.Pattern  # noqa: ANN001
) -> bool:
    """Checks whether a rule has certain options set to match a certain regex.

    If multiple options are set, it will return True if atleast one option matches the regex.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        names (Iterable[str]): names of the options
        regex (Union[re.Pattern, regex.Pattern]): regex to check for

    Returns:
    -------
        bool: True iff the rule has atleast one option matching the regex

    """
    for name in names:
        if is_rule_option_equal_to_regex(rule, name, regex):
            return True

    return False


def is_rule_option_one_of(
    rule: idstools.rule.Rule,
    name: str,
    possible_values: Union[Sequence[str], set[str]],
) -> bool:
    """Checks whether a rule has a certain option set to a one of certain values.

    If the option is set multiple times, it will return True if atleast one option matches a value.

    Args:
    ----
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        possible_values (Iterable[str]): values to check for

    Returns:
    -------
        bool: True iff the rule has the option set to one of the values atleast once

    """
    if not is_rule_option_set(rule, name):
        return False

    values = get_rule_options(rule, name)

    for value in values:
        if value in possible_values:
            return True

    return False


def get_rule_sticky_buffer_naming(rule: idstools.rule.Rule) -> list[tuple[str, str]]:
    """Returns a list of tuples containing the name of a sticky buffer, and the modifier alternative."""
    sticky_buffer_naming = []
    for option in rule["options"]:
        if option["name"] in STICKY_BUFFER_NAMING:
            sticky_buffer_naming.append(
                (option["name"], STICKY_BUFFER_NAMING[option["name"]]),
            )

    return sticky_buffer_naming


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_all_variable_groups(rule: idstools.rule.Rule) -> list[str]:
    """Returns a list of variable groups such as $HTTP_SERVERS in a rule."""
    variable_groups = []
    for name in (
        "source_addr",
        "source_port",
        "direction",
        "dest_addr",
        "dest_port",
    ):
        if is_rule_option_set(rule, name):
            value = get_rule_option(rule, name)
            assert value is not None
            variable_groups += get_variable_groups(value)

    return variable_groups


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_rule_option_positions(rule: idstools.rule.Rule, name: str) -> Sequence[int]:
    """Finds the positions of an option in the rule body."""
    positions = []
    for i, option in enumerate(rule["options"]):
        if option["name"] == name:
            positions.append(i)

    if len(positions) == 0 and is_rule_option_set(rule, name):
        msg = f"Cannot determine position of {name} option since it is not part of the rule body."
        logger.critical(msg)
        raise ValueError(msg)

    return tuple(sorted(positions))


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_rule_option_position(rule: idstools.rule.Rule, name: str) -> Optional[int]:
    """Finds the position of an option in the rule body.

    Return None if the option is not set or set multiple times.
    """
    positions = get_rule_option_positions(rule, name)

    if len(positions) == 0:
        logger.debug(
            "Cannot unambigously determine the position of the %s option since it it not set.",
            name,
        )
        return None

    if len(positions) == 1:
        return positions[0]

    logger.debug(
        "Cannot unambigously determine the position of the %s option since it is set multiple times.",
        name,
    )
    return None


def is_rule_option_first(rule: idstools.rule.Rule, name: str) -> Optional[int]:
    """Checks if a rule option is positioned at the beginning of the body."""
    position = get_rule_option_position(rule, name)

    if position is None:
        logger.debug("Cannot unambiguously determine if option %s first.", name)
        return None

    if position == 0:
        return True

    return False


def is_rule_option_last(rule: idstools.rule.Rule, name: str) -> Optional[bool]:
    """Checks if a rule option is positioned at the end of the body."""
    position = get_rule_option_position(rule, name)

    if position is None:
        logger.debug("Cannot unambiguously determine if option %s last.", name)
        return None

    if position == len(rule["options"]) - 1:
        return True

    return False


def get_rule_options_positions(
    rule: idstools.rule.Rule,
    names: Iterable[str],
) -> Iterable[int]:
    """Finds the positions of several options in the rule body."""
    return _get_rule_options_positions(rule, tuple(sorted(names)))


@lru_cache(maxsize=LRU_CACHE_SIZE)
def _get_rule_options_positions(
    rule: idstools.rule.Rule,
    names: Iterable[str],
) -> Iterable[int]:
    positions = []

    for name in names:
        positions.extend(get_rule_option_positions(rule, name))

    return tuple(sorted(positions))


def is_rule_option_put_before(
    rule: idstools.rule.Rule,
    name: str,
    other_names: Union[Sequence[str], set[str]],
) -> Optional[bool]:
    """Checks whether a rule option is placed before one or more other options."""
    return _is_rule_option_put_before(rule, name, tuple(sorted(other_names)))


@lru_cache(maxsize=LRU_CACHE_SIZE)
def _is_rule_option_put_before(
    rule: idstools.rule.Rule,
    name: str,
    other_names: Union[Sequence[str], set[str]],
) -> Optional[bool]:
    if len(other_names) == 0:
        logger.debug(
            "Cannot unambiguously determine if option %s is put before empty Iterable of other options.",
            name,
        )
        return None

    positions = get_rule_option_positions(rule, name)

    if name in other_names:
        logger.debug("Excluding name %s from other_names because of overlap.", name)
        other_names = set(other_names).difference({name})

    other_positions = get_rule_options_positions(rule, other_names)

    for other_position in other_positions:
        for position in positions:
            if position < other_position:
                return True
    return False


@lru_cache(maxsize=LRU_CACHE_SIZE)
def is_rule_option_always_put_before(
    rule: idstools.rule.Rule,
    name: str,
    other_names: Union[Sequence[str], set[str]],
) -> Optional[bool]:
    """Checks whether a rule option is placed before one or more other options."""
    if len(other_names) == 0:
        logger.debug(
            "Cannot unambiguously determine if option %s is put before empty Iterable of other options.",
            name,
        )
        return None

    positions = get_rule_option_positions(rule, name)

    if name in other_names:
        logger.debug("Excluding name %s from other_names because of overlap.", name)
        other_names = set(other_names).difference({name})

    other_positions = get_rule_options_positions(rule, other_names)

    for other_position in other_positions:
        for position in positions:
            if position >= other_position:
                return False
    return True


def are_rule_options_put_before(
    rule: idstools.rule.Rule,
    names: Union[Sequence[str], set[str]],
    other_names: Union[Sequence[str], set[str]],
) -> Optional[bool]:
    """Checks whether rule options are placed before one or more other options."""
    if len(other_names) == 0:
        logger.debug(
            "Cannot unambiguously determine if an empty Iterable of options are put before other options %s.",
            other_names,
        )
        return None
    if len(other_names) == 0:
        logger.debug(
            "Cannot unambiguously determine if options %s are put before empty Iterable of other options.",
            names,
        )
        return None

    for name in names:
        if is_rule_option_put_before(rule, name, other_names):
            return True
    return False


def are_rule_options_always_put_before(
    rule: idstools.rule.Rule,
    names: Iterable[str],
    other_names: Sequence[str],
) -> Optional[bool]:
    """Checks whether rule options are placed before one or more other options."""
    if len(other_names) == 0:
        logger.debug(
            "Cannot unambiguously determine if an empty Iterable of options are put before other options %s.",
            other_names,
        )
        return None
    if len(other_names) == 0:
        logger.debug(
            "Cannot unambiguously determine if options %s are put before empty Iterable of other options.",
            names,
        )
        return None

    for name in names:
        if not is_rule_option_put_before(rule, name, other_names):
            return False
    return True


@lru_cache(maxsize=LRU_CACHE_SIZE)
def select_rule_options_by_regex(
    rule: idstools.rule.Rule,
    regex: regex_provider.Pattern,
) -> Iterable[str]:
    """Selects rule options present in rule matching a regular expression."""
    options = []

    for option in rule["options"]:
        name = option["name"]
        if regex_provider.match(regex, name):
            options.append(name)

    return tuple(sorted(options))


def get_flow_options(rule: idstools.rule.Rule) -> Sequence[str]:
    """Returns a list of flow options set in a rule.

    Notably ignores `flow.*` options, but only looks at `flow:.*`
    """
    flow_option = get_rule_option(rule, "flow")
    if flow_option is None:
        flow_options = []
    else:
        flow_options = [option.strip() for option in flow_option.split(",")]

    return flow_options
