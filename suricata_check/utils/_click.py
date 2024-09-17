import logging

import click


class ClickHandler(logging.Handler):
    """Handler to color and write logging messages for the click module."""

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
