import logging

import click


class ClickHandler(logging.Handler):
    """Handler to color and write logging messages for the click module."""

    def emit(self: "ClickHandler", record: logging.LogRecord) -> None:
        """Log the record via click stdout with appropriate colors."""
        msg = self.format(record)

        if record.levelno == logging.getLevelName("DEBUG"):
            click.secho(msg, color=True, dim=True)
        if record.levelno == logging.getLevelName("INFO"):
            click.secho(msg, color=True)
        if record.levelno == logging.getLevelName("WARNING"):
            click.secho(msg, color=True, bold=True, fg="yellow")
        if record.levelno == logging.getLevelName("ERROR"):
            click.secho(msg, color=True, bold=True, fg="red")
        if record.levelno == logging.getLevelName("CRITICAL"):
            click.secho(msg, color=True, bold=True, blink=True, fg="red")
