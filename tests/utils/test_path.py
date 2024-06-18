import os
import shutil
import sys

import click
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check


@pytest.mark.serial()
def test_find_rules_file():
    full_path = os.path.abspath("tests/data/temp/test.rules")

    # Prepare temp folder
    if not os.path.exists("tests/data/temp"):
        os.makedirs("tests/data/temp")
    if os.path.exists(full_path):
        os.remove(full_path)
    shutil.copyfile("tests/data/test.rules", "tests/data/temp/test.rules")

    # Do tests
    result = suricata_check.utils.find_rules_file(os.path.abspath("tests/data/temp"))
    assert result == full_path

    result = suricata_check.utils.find_rules_file(full_path)
    assert result == full_path

    with pytest.raises(click.BadParameter):
        suricata_check.utils.find_rules_file(".")

    # Cleanup temp folder
    os.remove(full_path)
    os.rmdir("tests/data/temp")
