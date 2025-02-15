"""The `suricata_check.utils.checker` module contains several utilities for developing rule checkers."""

import logging
from collections.abc import Iterable, Sequence
from functools import lru_cache
from typing import Optional, Union

import idstools.rule

from suricata_check.utils.regex import (
    ALL_DETECTION_KEYWORDS,
    ALL_KEYWORDS,
    ALL_METADATA_KEYWORDS,
    BUFFER_KEYWORDS,
    STICKY_BUFFER_NAMING,
    get_regex_provider,
    get_variable_groups,
)

_LRU_CACHE_SIZE = 10


_logger = logging.getLogger(__name__)

_regex_provider = get_regex_provider()


def check_rule_option_recognition(rule: idstools.rule.Rule) -> None:
    """Checks whether all rule options and metadata options are recognized.

    Unrecognized options will be logged as a warning in `suricata-check.log`
    """
    for option in rule["options"]:
        name = option["name"]
        if name not in ALL_KEYWORDS:
            _logger.warning(
                "Option %s from rule %s is not recognized.",
                name,
                rule["sid"],
            )

    for option in rule["metadata"]:
        name = _regex_provider.split(r"\s+", option)[0]
        if name not in ALL_METADATA_KEYWORDS:
            _logger.warning(
                "Metadata option %s from rule %s is not recognized.",
                name,
                rule["sid"],
            )


def is_rule_option_set(rule: idstools.rule.Rule, name: str) -> bool:
    """Checks whether a rule has a certain option set.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option

    Returns:
        bool: True iff the option is set atleast once

    """
    return __is_rule_option_set(rule, name)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __is_rule_option_set(rule: idstools.rule.Rule, name: str) -> bool:
    if name not in (
        "action",
        "proto",
        "source_addr",
        "source_port",
        "direction",
        "dest_addr",
        "dest_port",
    ):
        if name not in ALL_KEYWORDS:
            _logger.warning("Requested a non-recognized keyword: %s", name)

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


def get_rule_suboptions(
    rule: idstools.rule.Rule, name: str, warn: bool = True
) -> Sequence[tuple[str, Optional[str]]]:
    """Returns a list of suboptions set in a rule."""
    values = get_rule_options(rule, name)
    valid_suboptions: list[tuple[str, Optional[str]]] = []
    for value in values:
        if value is None:
            continue
        values = value.split(",")
        suboptions: list[Optional[tuple[str, Optional[str]]]] = [
            __split_suboption(suboption, warn=warn) for suboption in values
        ]
        # Filter out suboptions that could not be parsed
        valid_suboptions += [
            suboption for suboption in suboptions if suboption is not None
        ]

    return valid_suboptions


def __split_suboption(
    suboption: str, warn: bool
) -> Optional[tuple[str, Optional[str]]]:
    suboption = suboption.strip()

    splitted = suboption.split(" ")
    splitted = [s.strip() for s in splitted]

    if len(splitted) == 1:
        return (splitted[0], None)
    if len(splitted) == 2:  # noqa: PLR2004
        return tuple(splitted)  # type: ignore reportReturnType

    if warn:
        _logger.warning("Failed to split suboption: %s", suboption)

    return None


def is_rule_suboption_set(rule: idstools.rule.Rule, name: str, sub_name: str) -> bool:
    """Checks if a suboption within an option is set."""
    suboptions = get_rule_suboptions(rule, name)
    _logger.debug(suboptions)

    if sub_name in [suboption[0] for suboption in suboptions]:
        return True

    return False


def get_rule_suboption(
    rule: idstools.rule.Rule, name: str, sub_name: str
) -> Optional[str]:
    """Returns a suboption within an option is set."""
    suboptions = get_rule_suboptions(rule, name)

    for suboption in suboptions:
        if sub_name == suboption[0]:
            return suboption[1]

    msg = f"Option {name} not found in rule."
    _logger.debug(msg)
    return None


def count_rule_options(
    rule: idstools.rule.Rule,
    name: Union[str, Iterable[str]],
) -> int:
    """Counts how often an option is set in a rule.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (Union[str, Iterable[str]]): name or names of the option

    Returns:
        int: The number of times an option is set

    """
    if not isinstance(name, str):
        name = tuple(sorted(name))
    return __count_rule_options(rule, name)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __count_rule_options(
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
        if name not in ALL_KEYWORDS:
            _logger.warning("Requested a non-recognized keyword: %s", name)

        for option in rule["options"]:
            if option["name"] == name:
                count += 1

    if count == 0 and is_rule_option_set(rule, name):
        count = 1

    return count


def get_rule_option(rule: idstools.rule.Rule, name: str) -> Optional[str]:
    """Retrieves one option of a rule with a certain name.

    If an option is set multiple times, it returns only one indeterminately.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option

    Returns:
        Optional[str]: The value of the option or None if it was not set.

    """
    return __get_rule_option(rule, name)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __get_rule_option(rule: idstools.rule.Rule, name: str) -> Optional[str]:
    options = get_rule_options(rule, name)

    if len(options) == 0:
        msg = f"Option {name} not found in rule."
        _logger.debug(msg)
        return None

    if len(options) == 0:
        msg = f"Cannot unambiguously determine the value of {name} because it is set multiple times."
        _logger.warning(msg)
        return None

    return options[0]


def get_rule_options(
    rule: idstools.rule.Rule,
    name: Union[str, Iterable[str]],
) -> Sequence[Optional[str]]:
    """Retrieves all options of a rule with a certain name.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (Union[str, Iterable[str]]): name or names of the option

    Returns:
        Sequence[str]: The values of the option.

    """
    if not isinstance(name, str):
        name = tuple(sorted(name))
    return __get_rule_options(rule, name)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __get_rule_options(
    rule: idstools.rule.Rule,
    name: Union[str, Iterable[str]],
    warn_not_found: bool = True,
) -> Sequence[str]:
    values = []

    if not isinstance(name, str):
        for single_name in name:
            values.extend(__get_rule_options(rule, single_name, warn_not_found=False))
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
        if name not in ALL_KEYWORDS:
            _logger.warning("Requested a non-recognized keyword: %s", name)

        for option in rule["options"]:
            if option["name"] == name:
                values.append(option["value"])
    elif name in rule:
        values.append(rule[name])

    if warn_not_found and len(values) == 0:
        msg = f"Option {name} not found in rule {rule}."
        _logger.debug(msg)

    return values


def is_rule_option_equal_to(rule: idstools.rule.Rule, name: str, value: str) -> bool:
    """Checks whether a rule has a certain option set to a certain value.

    If the option is set multiple times, it will return True if atleast one option matches the value.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        value (str): value to check for

    Returns:
        bool: True iff the rule has the option set to the value atleast once

    """
    if not is_rule_option_set(rule, name):
        return False

    values = get_rule_options(rule, name)

    for val in values:
        if val == value:
            return True

    return False


def is_rule_suboption_equal_to(
    rule: idstools.rule.Rule, name: str, sub_name: str, value: str
) -> bool:
    """Checks whether a rule has a certain suboption set to a certain value.

    If the suboption is set multiple times, it will return True if atleast one option matches the value.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        sub_name (str): name of the suboption
        value (str): value to check for

    Returns:
        bool: True iff the rule has the option set to the value atleast once

    """
    if not is_rule_suboption_set(rule, name, sub_name):
        return False

    values = get_rule_suboptions(rule, name)

    for key, val in values:
        if key == sub_name and val == value:
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
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        regex (Union[re.Pattern, regex.Pattern]): regex to check for

    Returns:
        bool: True iff the rule has atleast one option matching the regex

    """
    if not is_rule_option_set(rule, name):
        return False

    values = get_rule_options(rule, name)

    for value in values:
        if value is None:
            continue
        if regex.match(value) is not None:
            return True

    return False


def is_rule_suboption_equal_to_regex(
    rule: idstools.rule.Rule,
    name: str,
    sub_name: str,
    regex,  # re.Pattern or regex.Pattern  # noqa: ANN001
) -> bool:
    """Checks whether a rule has a certain option set to match a certain regex.

    If the option is set multiple times, it will return True if atleast one option matches the regex.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        sub_name (str): name of the suboption
        regex (Union[re.Pattern, regex.Pattern]): regex to check for

    Returns:
        bool: True iff the rule has atleast one option matching the regex

    """
    if not is_rule_suboption_set(rule, name, sub_name):
        return False

    values = get_rule_suboptions(rule, name)

    for key, value in values:
        if key == sub_name and regex.match(value) is not None:
            return True

    return False


def is_rule_option_always_equal_to_regex(
    rule: idstools.rule.Rule,
    name: str,
    regex,  # re.Pattern or regex.Pattern  # noqa: ANN001
) -> Optional[bool]:
    """Checks whether a rule has a certain option set to match a certain regex.

    If the option is set multiple times, it will return True if all options match the regex.
    Returns none if the rule option is not set.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        regex (Union[re.Pattern, regex.Pattern]): regex to check for

    Returns:
        bool: True iff the rule has all options matching the regex

    """
    if not is_rule_option_set(rule, name):
        return None

    values = get_rule_options(rule, name)

    for value in values:
        if value is None:
            return False
        if regex.match(value) is None:
            return False

    return True


def is_rule_suboption_always_equal_to_regex(
    rule: idstools.rule.Rule,
    name: str,
    sub_name: str,
    regex,  # re.Pattern or regex.Pattern  # noqa: ANN001
) -> Optional[bool]:
    """Checks whether a rule has a certain option set to match a certain regex.

    If the option is set multiple times, it will return True if all options match the regex.
    Returns none if the rule option is not set.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        sub_name (str): name of the suboption
        regex (Union[re.Pattern, regex.Pattern]): regex to check for

    Returns:
        bool: True iff the rule has all options matching the regex

    """
    if not is_rule_suboption_set(rule, name, sub_name):
        return None

    values = get_rule_suboptions(rule, name)

    for key, value in values:
        if key == sub_name and regex.match(value) is None:
            return False

    return True


def are_rule_options_equal_to_regex(
    rule: idstools.rule.Rule,
    names: Iterable[str],
    regex,  # re.Pattern or regex.Pattern  # noqa: ANN001
) -> bool:
    """Checks whether a rule has certain options set to match a certain regex.

    If multiple options are set, it will return True if atleast one option matches the regex.

    Args:
        rule (idstools.rule.Rule): rule to be inspected
        names (Iterable[str]): names of the options
        regex (Union[re.Pattern, regex.Pattern]): regex to check for

    Returns:
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
        rule (idstools.rule.Rule): rule to be inspected
        name (str): name of the option
        possible_values (Iterable[str]): values to check for

    Returns:
        bool: True iff the rule has the option set to one of the values atleast once

    """
    if not is_rule_option_set(rule, name):
        return False

    values = get_rule_options(rule, name)

    for value in values:
        if value is None:
            continue
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


def get_all_variable_groups(rule: idstools.rule.Rule) -> list[str]:
    """Returns a list of variable groups such as $HTTP_SERVERS in a rule."""
    return __get_all_variable_groups(rule)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __get_all_variable_groups(rule: idstools.rule.Rule) -> list[str]:
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


def get_rule_option_positions(
    rule: idstools.rule.Rule, name: str, sequence: Optional[tuple[str, ...]] = None
) -> Sequence[int]:
    """Finds the positions of an option in the rule body.

    Optionally takes a sequence of options to use instead of `rule['options']`.
    """
    return __get_rule_option_positions(rule, name, sequence=sequence)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __get_rule_option_positions(
    rule: idstools.rule.Rule, name: str, sequence: Optional[tuple[str, ...]] = None
) -> Sequence[int]:
    provided_sequence = True
    if sequence is None:
        sequence = tuple(option["name"] for option in rule["options"])
        provided_sequence = False

    positions = []
    for i, option in enumerate(sequence):
        if option == name:
            positions.append(i)

    if not provided_sequence and len(positions) == 0 and is_rule_option_set(rule, name):
        msg = f"Cannot determine position of {name} option since it is not part of the sequence of detection keywords."
        _logger.critical(msg)
        raise ValueError(msg)

    return tuple(sorted(positions))


def get_rule_option_position(rule: idstools.rule.Rule, name: str) -> Optional[int]:
    """Finds the position of an option in the rule body.

    Return None if the option is not set or set multiple times.
    """
    return __get_rule_option_position(rule, name)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __get_rule_option_position(rule: idstools.rule.Rule, name: str) -> Optional[int]:
    positions = get_rule_option_positions(rule, name)

    if len(positions) == 0:
        _logger.debug(
            "Cannot unambigously determine the position of the %s option since it it not set.",
            name,
        )
        return None

    if len(positions) == 1:
        return positions[0]

    _logger.debug(
        "Cannot unambigously determine the position of the %s option since it is set multiple times.",
        name,
    )
    return None


def is_rule_option_first(rule: idstools.rule.Rule, name: str) -> Optional[int]:
    """Checks if a rule option is positioned at the beginning of the body."""
    position = get_rule_option_position(rule, name)

    if position is None:
        _logger.debug("Cannot unambiguously determine if option %s first.", name)
        return None

    if position == 0:
        return True

    return False


def is_rule_option_last(rule: idstools.rule.Rule, name: str) -> Optional[bool]:
    """Checks if a rule option is positioned at the end of the body."""
    position = get_rule_option_position(rule, name)

    if position is None:
        _logger.debug("Cannot unambiguously determine if option %s last.", name)
        return None

    if position == len(rule["options"]) - 1:
        return True

    return False


def get_rule_options_positions(
    rule: idstools.rule.Rule,
    names: Iterable[str],
    sequence: Optional[Iterable[str]] = None,
) -> Iterable[int]:
    """Finds the positions of several options in the rule body."""
    return __get_rule_options_positions(
        rule, tuple(sorted(names)), sequence=tuple(sequence) if sequence else None
    )


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __get_rule_options_positions(
    rule: idstools.rule.Rule,
    names: Iterable[str],
    sequence: Optional[tuple[str, ...]] = None,
) -> Iterable[int]:
    positions = []

    for name in names:
        positions.extend(get_rule_option_positions(rule, name, sequence=sequence))

    return tuple(sorted(positions))


def is_rule_option_put_before(
    rule: idstools.rule.Rule,
    name: str,
    other_names: Union[Sequence[str], set[str]],
    sequence: Optional[Iterable[str]] = None,
) -> Optional[bool]:
    """Checks whether a rule option is placed before one or more other options."""
    return __is_rule_option_put_before(
        rule,
        name,
        tuple(sorted(other_names)),
        sequence=tuple(sequence) if sequence else None,
    )


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __is_rule_option_put_before(
    rule: idstools.rule.Rule,
    name: str,
    other_names: Union[Sequence[str], set[str]],
    sequence: Optional[tuple[str, ...]] = None,
) -> Optional[bool]:
    if len(other_names) == 0:
        _logger.debug(
            "Cannot unambiguously determine if option %s is put before empty Iterable of other options.",
            name,
        )
        return None

    positions = get_rule_option_positions(rule, name, sequence=sequence)

    if name in other_names:
        _logger.debug("Excluding name %s from other_names because of overlap.", name)
        other_names = set(other_names).difference({name})

    other_positions = get_rule_options_positions(rule, other_names, sequence=sequence)

    for other_position in other_positions:
        for position in positions:
            if position < other_position:
                return True
    return False


def is_rule_option_always_put_before(
    rule: idstools.rule.Rule,
    name: str,
    other_names: Union[Sequence[str], set[str]],
    sequence: Optional[Iterable[str]] = None,
) -> Optional[bool]:
    """Checks whether a rule option is placed before one or more other options."""
    return __is_rule_option_always_put_before(
        rule,
        name,
        tuple(sorted(other_names)),
        sequence=tuple(sequence) if sequence else None,
    )


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __is_rule_option_always_put_before(
    rule: idstools.rule.Rule,
    name: str,
    other_names: Union[Sequence[str], set[str]],
    sequence: Optional[tuple[str, ...]] = None,
) -> Optional[bool]:
    if len(other_names) == 0:
        _logger.debug(
            "Cannot unambiguously determine if option %s is put before empty Iterable of other options.",
            name,
        )
        return None

    positions = get_rule_option_positions(rule, name, sequence=sequence)

    if name in other_names:
        _logger.debug("Excluding name %s from other_names because of overlap.", name)
        other_names = set(other_names).difference({name})

    other_positions = get_rule_options_positions(rule, other_names, sequence=sequence)

    for other_position in other_positions:
        for position in positions:
            if position >= other_position:
                return False
    return True


def are_rule_options_put_before(
    rule: idstools.rule.Rule,
    names: Union[Sequence[str], set[str]],
    other_names: Union[Sequence[str], set[str]],
    sequence: Optional[Iterable[str]] = None,
) -> Optional[bool]:
    """Checks whether rule options are placed before one or more other options."""
    if len(other_names) == 0:
        _logger.debug(
            "Cannot unambiguously determine if an empty Iterable of options are put before other options %s.",
            other_names,
        )
        return None
    if len(other_names) == 0:
        _logger.debug(
            "Cannot unambiguously determine if options %s are put before empty Iterable of other options.",
            names,
        )
        return None

    for name in names:
        if is_rule_option_put_before(rule, name, other_names, sequence=sequence):
            return True
    return False


def are_rule_options_always_put_before(
    rule: idstools.rule.Rule,
    names: Iterable[str],
    other_names: Sequence[str],
    sequence: Optional[Iterable[str]] = None,
) -> Optional[bool]:
    """Checks whether rule options are placed before one or more other options."""
    if len(other_names) == 0:
        _logger.debug(
            "Cannot unambiguously determine if an empty Iterable of options are put before other options %s.",
            other_names,
        )
        return None
    if len(other_names) == 0:
        _logger.debug(
            "Cannot unambiguously determine if options %s are put before empty Iterable of other options.",
            names,
        )
        return None

    for name in names:
        if not is_rule_option_put_before(rule, name, other_names, sequence=sequence):
            return False
    return True


def select_rule_options_by_regex(
    rule: idstools.rule.Rule, regex  # noqa: ANN001
) -> Iterable[str]:
    """Selects rule options present in rule matching a regular expression."""
    return __select_rule_options_by_regex(rule, regex)


@lru_cache(maxsize=_LRU_CACHE_SIZE)
def __select_rule_options_by_regex(
    rule: idstools.rule.Rule, regex  # noqa: ANN001
) -> Iterable[str]:
    options = []

    for option in rule["options"]:
        name = option["name"]
        if _regex_provider.match(regex, name):
            options.append(name)

    return tuple(sorted(options))


def get_rule_keyword_sequences(
    rule: idstools.rule.Rule,
    seperator_keywords: Iterable[str] = BUFFER_KEYWORDS,
    included_keywords: Iterable[str] = ALL_DETECTION_KEYWORDS,
) -> Sequence[tuple[str, ...]]:
    """Returns a sequence of sequences of detection options in a rule."""
    sequences: list[list[str]] = []

    # Relies on the assumption that the order of options in the rule is preserved while parsing
    sequence_i = -1
    first_seperator_seen = False
    for option in rule["options"]:
        name = option["name"]
        if name in seperator_keywords:
            if not first_seperator_seen:
                if len(sequences) > 0:
                    sequences[sequence_i].append(name)
                else:
                    sequence_i += 1
                    sequences.append([name])
            else:
                sequence_i += 1
                sequences.append([name])
            first_seperator_seen = True
        elif name in included_keywords and sequence_i == -1:
            sequence_i += 1
            sequences.append([name])
        elif name in included_keywords:
            sequences[sequence_i].append(name)

    if len(sequences) == 0:
        _logger.debug(
            "No sequences found separated by %s in rule %s",
            seperator_keywords,
            rule["raw"],
        )
        return ()

    for sequence in sequences:
        assert len(sequence) > 0

    result = tuple(tuple(sequence) for sequence in sequences)

    _logger.debug(
        "Detected sequences %s separated by %s in rule %s",
        result,
        seperator_keywords,
        rule["raw"],
    )

    return result
