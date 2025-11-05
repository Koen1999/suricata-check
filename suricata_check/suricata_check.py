"""The `suricata_check.suricata_check` module contains the command line utility and the main program logic."""

import atexit
import configparser
import io
import json
import logging
import logging.handlers
import multiprocessing
import os
import sys
from collections.abc import Sequence
from typing import (
    Any,
    Callable,
    Literal,
    Optional,
    TypeVar,
    Union,
)

import click

import suricata_check
from suricata_check.utils.checker_typing import Rule

_AnyCallable = Callable[..., Any]
_FC = TypeVar("_FC", bound=Union[_AnyCallable, click.Command])

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# Add suricata-check to the front of the PATH, such that the version corresponding to the CLI is used.
_suricata_check_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if sys.path[0] != _suricata_check_path:
    sys.path.insert(0, _suricata_check_path)

from suricata_check import (  # noqa: E402
    __version__,
    check_for_update,
    get_dependency_versions,
)
from suricata_check._checkers import get_checkers  # noqa: E402
from suricata_check._output import (  # noqa: E402
    summarize_output,
    summarize_rule,
    write_output,
)
from suricata_check.checkers.interface import CheckerInterface  # noqa: E402
from suricata_check.utils._click import ClickHandler, help_option  # noqa: E402
from suricata_check.utils._path import find_rules_file  # noqa: E402
from suricata_check.utils.checker import (  # noqa: E402
    check_rule_option_recognition,
    get_rule_suboption,
)
from suricata_check.utils.checker_typing import (  # noqa: E402
    InvalidRuleError,
    OutputReport,
    RuleReport,
)
from suricata_check.utils.regex import get_regex_provider, is_valid_rule  # noqa: E402

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]

# Define all command line arguments and their properties
CLI_ARGUMENTS: dict[str, dict[str, Any]] = {
    "rules": {
        "help": "Path to Suricata rules to provide check on.",
        "show_default": True,
        "type": str,
        "required": False,
        "default": ".",
        "cli_options": ["-r"],
    },
    "single_rule": {
        "help": "A single Suricata rule to be checked",
        "show_default": False,
        "type": str,
        "required": False,
        "default": None,
        "cli_options": ["-s"],
    },
    "out": {
        "help": "Path to suricata-check output folder.",
        "show_default": True,
        "type": str,
        "required": False,
        "default": ".",
        "cli_options": ["-o"],
    },
    "log_level": {
        "help": f"Verbosity level for logging. Can be one of {LOG_LEVELS}",
        "show_default": True,
        "type": str,
        "required": False,
        "default": "DEBUG",
    },
    "gitlab": {
        "help": "Flag to create CodeClimate output report for GitLab CI/CD.",
        "show_default": True,
        "type": bool,
        "required": False,
        "default": False,
        "is_flag": True,
    },
    "github": {
        "help": "Flag to write workflow commands to stdout for GitHub CI/CD.",
        "show_default": True,
        "type": bool,
        "required": False,
        "default": False,
        "is_flag": True,
    },
    "evaluate_disabled": {
        "help": "Flag to evaluate disabled rules.",
        "show_default": True,
        "type": bool,
        "required": False,
        "default": False,
        "is_flag": True,
    },
    "issue_severity": {
        "help": f"Verbosity level for detected issues. Can be one of {LOG_LEVELS}",
        "show_default": True,
        "type": str,
        "required": False,
        "default": "INFO",
    },
    "include_all": {
        "help": "Flag to indicate all checker codes should be enabled.",
        "show_default": True,
        "type": bool,
        "required": False,
        "default": False,
        "is_flag": True,
        "cli_options": ["-a"],
    },
    "include": {
        "help": "List of all checker codes to enable.",
        "show_default": True,
        "type": tuple,
        "required": False,
        "default": (),
        "multiple": True,
        "cli_options": ["-i"],
    },
    "exclude": {
        "help": "List of all checker codes to disable.",
        "show_default": True,
        "type": tuple,
        "required": False,
        "default": (),
        "multiple": True,
        "cli_options": ["-e"],
    },
}
CLI_ARGUMENT_TYPE = Optional[Union[str, bool, tuple]]

_logger = logging.getLogger(__name__)

_regex_provider = get_regex_provider()


def __create_click_option(name: str, props: dict[str, Any]) -> Callable[[_FC], _FC]:
    """Create a click.option decorator from argument properties."""
    kwargs = {
        "help": props["help"],
        "show_default": props["show_default"],
        "default": props.get("default"),
        "is_flag": props.get("is_flag", False),
        "multiple": props.get("multiple", False),
    }

    # Add any additional CLI options (like -r, -s, etc.)
    cli_opts = props.get("cli_options", [])
    args = [f"--{name.replace('_', '-')}", *cli_opts]

    return click.option(*args, **kwargs)


def __main_decorators() -> Callable[[Callable], click.Command]:
    """Create the CLI command with all options."""

    def decorator(f: Callable) -> click.Command:
        # Apply all options in reverse order (bottom to top)
        command = click.command()(f)
        command = help_option("-h", "--help")(command)

        # Add ini option first since it's needed before processing other options
        command = click.option(
            "--ini",
            help="Path to suricata-check.ini file to read configuration from.",
            show_default=True,
            type=str,
            default=None,
        )(command)

        # Apply options from CLI_ARGUMENTS
        for name, props in reversed(CLI_ARGUMENTS.items()):
            command = __create_click_option(name, props)(command)

        return command

    return decorator


@__main_decorators()
def main(**kwargs: dict[str, Any]) -> None:  # noqa: C901, PLR0915
    """The `suricata-check` command processes all rules inside a rules file and outputs a list of detected issues.

    Raises:
      BadParameter: If provided arguments are invalid.

      RuntimeError: If no checkers could be automatically discovered.

    """
    # Look for a ini file and parse it.
    ini_kwargs = get_ini_kwargs(
        str(kwargs["ini"]) if kwargs["ini"] is not None else None  # type: ignore reportUnnecessaryComparison
    )

    # Verify CLI argument types and get CLI arguments or use default arguments
    rules: str = __get_verified_kwarg(
        [kwargs, ini_kwargs], "rules"
    )  # pyright: ignore[reportAssignmentType]
    single_rule: Optional[str] = __get_verified_kwarg(
        [kwargs, ini_kwargs], "single_rule"
    )  # pyright: ignore[reportAssignmentType]
    out: str = __get_verified_kwarg(
        [kwargs, ini_kwargs], "out"
    )  # pyright: ignore[reportAssignmentType]
    log_level: LogLevel = __get_verified_kwarg(
        [kwargs, ini_kwargs], "log_level"
    )  # pyright: ignore[reportAssignmentType]
    gitlab: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "gitlab"
    )  # pyright: ignore[reportAssignmentType]
    github: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "github"
    )  # pyright: ignore[reportAssignmentType]
    evaluate_disabled: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "evaluate_disabled"
    )  # pyright: ignore[reportAssignmentType]
    issue_severity: LogLevel = __get_verified_kwarg(
        [kwargs, ini_kwargs], "issue_severity"
    )  # pyright: ignore[reportAssignmentType]
    include_all: bool = __get_verified_kwarg(
        [kwargs, ini_kwargs], "include_all"
    )  # pyright: ignore[reportAssignmentType]
    include: tuple[str, ...] = __get_verified_kwarg(
        [kwargs, ini_kwargs], "include"
    )  # pyright: ignore[reportAssignmentType]
    exclude: tuple[str, ...] = __get_verified_kwarg(
        [kwargs, ini_kwargs], "exclude"
    )  # pyright: ignore[reportAssignmentType]

    # Verify that out argument is valid
    if os.path.exists(out) and not os.path.isdir(out):
        raise click.BadParameter(f"Error: {out} is not a directory.")

    # Verify that log_level argument is valid
    if log_level not in LOG_LEVELS:
        raise click.BadParameter(f"Error: {log_level} is not a valid log level.")

    # Create out directory if non-existent
    if not os.path.exists(out):
        os.makedirs(out)

    # Setup logging from a seperate thread
    queue = multiprocessing.Manager().Queue()
    queue_handler = logging.handlers.QueueHandler(queue)

    click_handler = ClickHandler(
        github=github, github_level=getattr(logging, log_level)
    )
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=(queue_handler, click_handler),
        force=os.environ.get("SURICATA_CHECK_FORCE_LOGGING", "FALSE") == "TRUE",
    )

    file_handler = logging.FileHandler(
        filename=os.path.join(out, "suricata-check.log"),
        delay=True,
    )
    queue_listener = logging.handlers.QueueListener(
        queue,
        file_handler,
        respect_handler_level=True,
    )

    def _at_exit() -> None:
        """Cleans up logging listener and handlers before exiting."""
        queue_listener.enqueue_sentinel()
        queue_listener.stop()
        file_handler.flush()
        file_handler.close()
        atexit.unregister(_at_exit)

    atexit.register(_at_exit)

    queue_listener.start()

    # Log the arguments:
    _logger.info("Running suricata-check with the following arguments:")
    for arg in CLI_ARGUMENTS:
        _logger.info("%s: %s", arg, locals().get(arg))

    # Log the environment:
    _logger.debug("Platform: %s", sys.platform)
    _logger.debug("Python version: %s", sys.version)
    _logger.debug("suricata-check path: %s", _suricata_check_path)
    _logger.debug("suricata-check version: %s", __version__)
    for package, version in get_dependency_versions().items():
        _logger.debug("Dependency %s version: %s", package, version)

    check_for_update()

    # Verify that include and exclude arguments are valid
    if include_all and len(include) > 0:
        raise click.BadParameter(
            "Error: Cannot use --include-all and --include together."
        )
    if include_all:
        include = (".*",)

    # Verify that issue_severity argument is valid
    if issue_severity not in LOG_LEVELS:
        raise click.BadParameter(
            f"Error: {issue_severity} is not a valid issue severity or log level."
        )

    checkers = get_checkers(
        include, exclude, issue_severity=getattr(logging, issue_severity)
    )

    if single_rule is not None:
        __main_single_rule(out, single_rule, checkers)

        # Return here so no rules file is processed.
        _at_exit()
        return

    # Check if the rules argument is valid and find the rules file
    rules = find_rules_file(rules)

    output = process_rules_file(rules, evaluate_disabled, checkers=checkers)

    write_output(output, out, gitlab=gitlab, github=github, rules_file=rules)

    _at_exit()


def get_ini_kwargs(path: Optional[str]) -> dict[str, Any]:
    """Read configuration from INI file based on CLI_ARGUMENTS structure."""
    ini_kwargs: dict[str, Any] = {}
    if path is not None and not os.path.exists(path):
        raise click.BadParameter(
            f"Error: INI file provided in {path} but no options loaded"
        )

    # Use the default path if no path was provided
    if path is None:
        path = "suricata-check.ini"
        if not os.path.exists(path):
            return {}

    config_parser = configparser.ConfigParser(
        empty_lines_in_values=False,
        default_section="suricata-check",
        converters={"tuple": lambda x: tuple(json.loads(x))},
    )
    config_parser.read(path)

    # Process each argument defined in CLI_ARGUMENTS
    for arg_name, arg_props in CLI_ARGUMENTS.items():
        ini_key = arg_name.replace("_", "-")
        if not config_parser.has_option("suricata-check", ini_key):
            continue

        # Get the value based on the argument type
        if arg_props["type"] is bool:
            ini_kwargs[arg_name] = config_parser.getboolean("suricata-check", ini_key)
        elif arg_props["type"] is tuple:
            ini_kwargs[arg_name] = config_parser.gettuple("suricata-check", ini_key)  # type: ignore reportAttributeAccessIssue
        else:
            ini_kwargs[arg_name] = config_parser.get("suricata-check", ini_key)
            if arg_props["type"] is str:
                ini_kwargs[arg_name] = ini_kwargs[arg_name].strip('"')

    return ini_kwargs


def __get_verified_kwarg(
    kwargss: Sequence[dict[str, Any]],
    name: str,
) -> CLI_ARGUMENT_TYPE:
    for kwargs in kwargss:
        if name in kwargs:
            if kwargs[name] is None:
                if (
                    not CLI_ARGUMENTS[name]["required"]
                    and CLI_ARGUMENTS[name]["default"] is not None
                ):
                    return None
                return CLI_ARGUMENTS[name]["default"]

            if kwargs[name] is not CLI_ARGUMENTS[name]["default"]:
                if not isinstance(kwargs[name], CLI_ARGUMENTS[name]["type"]):
                    raise click.BadParameter(
                        f"""Error: \
                Argument `{name}` should have a value of type `{CLI_ARGUMENTS[name]["type"]}` \
                but has value {kwargs[name]} of type {kwargs[name].__class__} instead."""
                    )
                return kwargs[name]

    return CLI_ARGUMENTS[name]["default"]


def __main_single_rule(
    out: str, single_rule: str, checkers: Optional[Sequence[CheckerInterface]]
) -> None:
    rule: Optional[Rule] = suricata_check.rule.parse(single_rule)

    # Verify that a rule was parsed correctly.
    if rule is None:
        msg = f"Error parsing rule from user input: {single_rule}"
        _logger.critical(msg)
        raise click.BadParameter(f"Error: {msg}")

    if not is_valid_rule(rule):
        msg = f"Error parsing rule from user input: {single_rule}"
        _logger.critical(msg)
        raise click.BadParameter(f"Error: {msg}")

    _logger.debug("Processing rule: %s", rule["sid"])

    rule_report = analyze_rule(rule, checkers=checkers)

    write_output(OutputReport(rules=[rule_report]), out)


def process_rules_file(  # noqa: C901, PLR0912, PLR0915
    rules: str,
    evaluate_disabled: bool,
    checkers: Optional[Sequence[CheckerInterface]] = None,
) -> OutputReport:
    """Processes a rule file and returns a list of rules and their issues.

    Args:
    rules: A path to a Suricata rules file.
    evaluate_disabled: A flag indicating whether disabled rules should be evaluated.
    checkers: The checkers to be used when processing the rule file.

    Returns:
        A list of rules and their issues.

    Raises:
        RuntimeError: If no checkers could be automatically discovered.

    """
    if checkers is None:
        checkers = get_checkers()

    output = OutputReport()

    with (
        open(
            os.path.normpath(rules),
            buffering=io.DEFAULT_BUFFER_SIZE,
        ) as rules_fh,
    ):
        if len(checkers) == 0:
            msg = "No checkers provided for processing rules."
            _logger.error(msg)
            raise RuntimeError(msg)

        _logger.info("Processing rule file: %s", rules)

        collected_multiline_parts: Optional[str] = None
        multiline_begin_number: Optional[int] = None

        for number, line in enumerate(rules_fh.readlines(), start=1):
            # First work on collecting and parsing multiline rules
            if line.rstrip("\r\n").endswith("\\"):
                multiline_part = line.rstrip("\r\n")[:-1]

                if collected_multiline_parts is None:
                    collected_multiline_parts = multiline_part
                    multiline_begin_number = number
                else:
                    collected_multiline_parts += multiline_part.lstrip()

                continue

            # Process final part of multiline rule if one is being collected
            if collected_multiline_parts is not None:
                collected_multiline_parts += line.lstrip()

                rule_line = collected_multiline_parts.strip()

                collected_multiline_parts = None
            # If no multiline rule is being collected process as a potential single line rule
            else:
                if len(line.strip()) == 0:
                    continue

                if line.strip().startswith("#"):
                    if evaluate_disabled:
                        # Verify that this line is a rule and not a comment
                        if suricata_check.rule.parse(line) is None:
                            # Log the comment since it may be a invalid rule
                            _logger.warning(
                                "Ignoring comment on line %i: %s", number, line
                            )
                            continue
                    else:
                        # Skip the rule
                        continue

                rule_line = line.strip()

            try:
                rule: Optional[Rule] = suricata_check.rule.parse(rule_line)
            except suricata_check.rule.ParsingError:
                _logger.error(
                    "Internal error in parsing of rule on line %i: %s",
                    number,
                    rule_line,
                )
                rule = None

            # Parse comment and potential ignore comment to ignore rules
            ignore = __parse_type_ignore(rule)

            # Verify that a rule was parsed correctly.
            if rule is None:
                _logger.error("Error parsing rule on line %i: %s", number, rule_line)
                continue

            if not is_valid_rule(rule):
                _logger.error("Invalid rule on line %i: %s", number, rule_line)
                continue

            _logger.debug("Processing rule: %s on line %i", rule["sid"], number)

            rule_report: RuleReport = analyze_rule(
                rule,
                checkers=checkers,
                ignore=ignore,
            )
            rule_report.line_begin = multiline_begin_number or number
            rule_report.line_end = number

            output.rules.append(rule_report)

            multiline_begin_number = None

    _logger.info("Completed processing rule file: %s", rules)

    output.summary = summarize_output(output, checkers)

    return output


def __parse_type_ignore(rule: Optional[Rule]) -> Optional[Sequence[str]]:
    if rule is None:
        return None

    ignore_value = get_rule_suboption(rule, "metadata", "suricata-check")
    if ignore_value is None:
        return []

    return ignore_value.strip(' "').split(",")


def analyze_rule(
    rule: Rule,
    checkers: Optional[Sequence[CheckerInterface]] = None,
    ignore: Optional[Sequence[str]] = None,
) -> RuleReport:
    """Checks a rule and returns a dictionary containing the rule and a list of issues found.

    Args:
    rule: The rule to be checked.
    checkers: The checkers to be used to check the rule.
    ignore: Regular expressions to match checker codes to ignore

    Returns:
    A list of issues found in the rule.
    Each issue is typed as a `dict`.

    Raises:
    InvalidRuleError: If the rule does not follow the Suricata syntax.

    """
    if not is_valid_rule(rule):
        raise InvalidRuleError(rule["raw"])

    check_rule_option_recognition(rule)

    if checkers is None:
        checkers = get_checkers()

    rule_report: RuleReport = RuleReport(rule=rule)

    _logger.warning(ignore)

    compiled_ignore = (
        [_regex_provider.compile(r) for r in ignore] if ignore is not None else []
    )

    for checker in checkers:
        try:
            issues = checker.check_rule(rule)
            for r in compiled_ignore:
                issues = list(filter(lambda issue: r.match(issue.code) is None, issues))
            rule_report.add_issues(issues)
        except Exception as exception:  # noqa: BLE001
            _logger.warning(
                "Failed to run %s on rule: %s",
                checker.__class__.__name__,
                rule["raw"],
                extra={"exception": exception},
            )

    rule_report.summary = summarize_rule(rule_report, checkers)

    return rule_report


if __name__ == "__main__":
    main()
