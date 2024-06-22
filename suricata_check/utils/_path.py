import logging
import os

import click

_logger = logging.getLogger(__name__)


def find_rules_file(root: str) -> str:
    """Find the Suricata rules file in the given directory."""
    if not os.path.exists(root):
        msg = f"Error: {root} does not exist."
        _logger.critical(msg)
        raise click.BadParameter(f"Error: {msg}")

    is_root_dir = os.path.isdir(root)
    if not root.endswith(".rules") and not is_root_dir:
        msg = f"Error: {root} is not a rules file or directory."
        _logger.critical(msg)
        raise click.BadParameter(f"Error: {msg}")

    if not is_root_dir:
        rules_file = root
    else:
        full_path = os.path.abspath(root)
        _logger.info("Searching for Suricata rules file in %s", full_path)

        rules_files: list[str] = []
        for path, _, files in os.walk(root):
            for file in files:
                if file.endswith(".rules"):
                    rules_files.append(os.path.join(path, file))

        if len(rules_files) == 0:
            msg = f"No Suricata rules file found in {root}"
            _logger.critical(msg)
            raise click.BadParameter(f"Error: {msg}")
        if len(rules_files) > 1:
            msg = f"Multiple Suricata rules files found in {root}\n" + "\n".join(
                rules_files,
            )
            _logger.critical(msg)
            raise click.BadParameter(f"Error: {msg}")

        rules_file = rules_files[0]

    _logger.info("Found Suricata rules file: %s", rules_file)

    return rules_file
