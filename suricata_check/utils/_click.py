import gettext
import logging
from typing import Any, Callable, TypeVar

import click

from suricata_check._version import get_version

_AnyCallable = Callable[..., Any]
FC = TypeVar("FC", bound="_AnyCallable | click.Command")


def help_option(*param_decls: str, **kwargs: dict[str, Any]) -> Callable[[FC], FC]:
    """``--help`` option which immediately printsversion help info and exits.

    :param param_decls: One or more option names. Defaults to the single
        value ``"--help"``.
    :param kwargs: Extra arguments are passed to :func:`option`.
    """

    def show_help(
        ctx: click.Context, param: click.Parameter, value: bool  # noqa: ARG001
    ) -> None:
        """Callback that print the help page on ``<stdout>`` and exits."""
        click.echo("suricata-check {}\n".format(get_version()))

        if value and not ctx.resilient_parsing:
            click.echo(ctx.get_help(), color=ctx.color)
            ctx.exit()

    if not param_decls:
        param_decls = ("--help",)

    kwargs.setdefault("is_flag", True)  # pyright: ignore[reportArgumentType]
    kwargs.setdefault("expose_value", False)  # pyright: ignore[reportArgumentType]
    kwargs.setdefault("is_eager", True)  # pyright: ignore[reportArgumentType]
    kwargs.setdefault(
        "help",
        gettext.gettext(
            "Show this message and exit."
        ),  # pyright: ignore[reportArgumentType]
    )
    kwargs.setdefault("callback", show_help)  # pyright: ignore[reportArgumentType]

    return click.option(*param_decls, **kwargs)  # pyright: ignore[reportArgumentType]


class ClickHandler(logging.Handler):
    """Handler to color and write logging messages for the click module."""

    def __init__(
        self: "ClickHandler",
        level: int = 0,
        github: bool = False,
        github_level: int = logging.WARNING,
        **kwargs: dict,
    ) -> None:
        super().__init__(level, **kwargs)
        self.github = github
        self.github_level = github_level

    def emit(self: "ClickHandler", record: logging.LogRecord) -> None:
        """Log the record via click stdout with appropriate colors."""
        msg = self.format(record)

        if logging.getLevelName(record.levelno) == "DEBUG":
            click.secho(msg, color=True, dim=True)
        if logging.getLevelName(record.levelno) == "INFO":
            click.secho(msg, color=True)
        if logging.getLevelName(record.levelno) == "WARNING":
            click.secho(msg, color=True, bold=True, fg="yellow")
        if logging.getLevelName(record.levelno) == "ERROR":
            click.secho(msg, color=True, bold=True, fg="red")
        if logging.getLevelName(record.levelno) == "CRITICAL":
            click.secho(msg, color=True, bold=True, blink=True, fg="red")

        if self.github and record.levelno >= self.github_level:
            print(f"::debug::{msg}")  # noqa: T201
