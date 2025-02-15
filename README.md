# The `suricata-check` project

[![Static Badge](https://img.shields.io/badge/docs-suricata--check-blue)](https://suricata-check.teuwen.net/)
[![Python Version](https://img.shields.io/pypi/pyversions/suricata-check)](https://pypi.org/project/suricata-check)
[![PyPI](https://img.shields.io/pypi/status/suricata-check)](https://pypi.org/project/suricata-check)
[![GitHub License](https://img.shields.io/github/license/Koen1999/suricata-check)](https://github.com/Koen1999/suricata-check/blob/master/LICENSE)

[![Quick Test, Build, Lint](https://github.com/Koen1999/suricata-check/actions/workflows/python-pr.yml/badge.svg?event=push)](https://github.com/Koen1999/suricata-check/actions/workflows/python-pr.yml)
[![Extensive Test](https://github.com/Koen1999/suricata-check/actions/workflows/python-push.yml/badge.svg)](https://github.com/Koen1999/suricata-check/actions/workflows/python-push.yml)
[![Release](https://github.com/Koen1999/suricata-check/actions/workflows/python-release.yml/badge.svg)](https://github.com/Koen1999/suricata-check/actions/workflows/python-release.yml)


`suricata-check` is a command line utility to provide feedback on [Suricata](https://github.com/OISF/suricata) rules.
The tool can detect various issues including those covering syntax validity, interpretability, rule specificity, rule coverage, and efficiency.

## Features

- [Static analysis without Suricata installation for any operating system](https://suricata-check.teuwen.net/readme.html)
- [Simple CLI with options to work with any ruleset](https://suricata-check.teuwen.net/cli_usage.html)
- [Documented, Typed, and Tested API](https://suricata-check.teuwen.net/api_usage.html)
- [CI/CD integration with GitHub and GitLab](https://suricata-check.teuwen.net/ci_cd.html)
- [Visual Studio Code Extension](https://marketplace.visualstudio.com/items?itemName=Koen1999.suricata-check)
- [Easily extendable with custom checkers](https://suricata-check.teuwen.net/checker.html)

## Installation

### From PyPI

To install `suricata-check` from [PyPI](https://pypi.org/project/suricata-check/), simply run the following command:

```bash
pip install suricata-check[performance]
```

Installation should work out-of-the-box on any Operating System (OS) and has been tested on Windows and Linux (Fedora and Ubuntu).

### From source

To install `suricata-check` from source (potentially with local modifications), simply run the following commands:

```bash
git clone https://github.com/Koen1999/suricata-check
cd suricata-check
pip install -r requirements.txt
pytest
pip install .
```

This will install `suricata-check` from source, which should be fine considering it's a pure-python package.

## Usage

After installing `suricata-check`, you can use it from the command line:

```bash
suricata-check
```

This command will look for a file ending with `.rules` in the currrent working directory, and write output to the current working directory.

More details regarding the command line interface can be found below:

```
Usage: suricata_check.py [OPTIONS]

  The `suricata-check` command processes all rules inside a rules file and
  outputs a list of detected issues.

  Raises:   BadParameter: If provided arguments are invalid.

    RuntimeError: If no checkers could be automatically discovered.

Options:
  -i, --ini TEXT          Path to suricata-check.ini file to read
                          configuration from.
  -r, --rules TEXT        Path to Suricata rules to provide check on.
  -s, --single-rule TEXT  A single Suricata rule to be checked
  -o, --out TEXT          Path to suricata-check output folder.
  --log-level TEXT        Verbosity level for logging. Can be one of ('DEBUG',
                          'INFO', 'WARNING', 'ERROR')
  --gitlab                Flag to create CodeClimate output report for GitLab
                          CI/CD.
  --github                Flag to write workflow commands to stdout for GitHub
                          CI/CD.
  --evaluate-disabled     Flag to evaluate disabled rules.
  --issue-severity TEXT   Verbosity level for detected issues. Can be one of
                          ('DEBUG', 'INFO', 'WARNING', 'ERROR')
  -a, --include-all       Flag to indicate all checker codes should be
                          enabled.
  -i, --include TEXT      List of all checker codes to enable.
  -e, --exclude TEXT      List of all checker codes to disable.
  -h, --help              Show this message and exit.
```

Usage of suricata-check as a module is currently not documented in detail, but the type hints and docstrings in the code should provide a decent start.

## Output

The output of `suricata-check` is collected in a folder and spread across several files. Additionally, the most important output is visible in the terminal.

`suricata-check.log` contains log messages describing the executing flow of `suricata-check` and can be useful during development, as well as to detect potential issues with parsing rules or rule files.

`suricata-check-fast.log` contains a condensed overview of all issues found by `suricata-check` in individual rules and is useful during rule engineering as feedback points to further improve rules under development.

`suricata-check-stats.log` contains a very condensed overview of all issues found by `suricata-check` across all rules and is useful when reviewing the quality of an entire ruleset.

`suricata-check.jsonl` is a jsonlines log file containing all the issues presented in `suricata-check-fast.log` together with parsed versions of _all_ rules and is useful for programatically further processing output of `suricata-check`. An example use-case could be to selectively disable rules affected by certain issues to prevent low-quality rules inducing additional workload in Security Operations Centers.

## Issue codes

`suricata-check` employs various checkers, each emitting one or more _issue codes_.
The issue codes are grouped into several ranges, depending on the category of the checker.
Each issue group is explained in detail below.
For details regarding specific issues, we recommend you check the message of the issue as well as the test example rules under `tests/checkers`.

### Overview

| Issue identifier format | Description                                                 |
| ----------------------- | ----------------------------------------------------------- |
| M000                    | Rules pertaining to the detection of valid Suricata syntax. |
| S000                    | Rules derived from the Suricata Style Guide.                |
| P000,Q000                    | Rules based [Ruling the Unruly](https://doi.org/10.1145/3708821.3710823).                          |
| C000                    | Rules based on community issues, such as this GitHub.       |

### Mandatory issues

Rules starting with prefix _M_ indicate issues pertaining to the validity of Suricata rules.
Rules with _M_-type issues will most probably not be used by Suricata due to invalid syntax or missing fields.

Not all invalid rules wlll be reported through _M_-type issues as some rules can simply not be parsed to the point where these issues are detected.
Instead, you can detect these rules through the `ERROR` messages in `suricata-check.log`.

### Suricata Style Guide issues

Rules starting with prefix _S_ indicate issues pertaining to the adherence to the [Suricata Style Guide](https://github.com/sidallocation/suricata-style-guide).
Rules with _S_-type issues are likely to hint on interpretability or efficiency issues.

### Principle issues

Rules starting with prefix _P_ indicate issues relating to rule design principles posed in the [Ruling the Unruly](https://doi.org/10.1145/3708821.3710823) paper.
Rules with _P_-type issues can relate to a specificity and coverage.

### Community issues

Rules starting with prefix _C_ indicate issues posed by the community and are an extension on top of the other issue groups.
Rules with _C_-type issues can relate to a wide variety of issues.
You can propose your own community type issues that should be checked for in the [issues](https://github.com/Koen1999/suricata-check/issues) section.

## Contributing

If you would like to contribute, please check out [CONTRIBUTING.md](https://github.com/Koen1999/suricata-check/blob/master/CONTRIBUTING.md) some helpful suggestions and instructions.

## License

This project is licensed under the [European Union Public Licence (EUPL)](https://github.com/Koen1999/suricata-check/blob/master/LICENSE).

Note that extensions may be licensed under another license as detailed in [CONTRIBUTING.md](https://github.com/Koen1999/suricata-check/blob/master/CONTRIBUTING.md).
For example, the [suricata-check-extension-example](https://github.com/Koen1999/suricata-check-extension-example) project is licensed under the [Apache 2.0 license](https://github.com/Koen1999/suricata-check-extension-example/blob/master/LICENSE).

## Citations
If you use the source code, the tool, or otherwise draw from this work, please cite the following paper:

**Koen T. W. Teuwen, Tom Mulders, Emmanuele Zambon, and Luca Allodi. 2025. Ruling the Unruly: Designing Effective, Low-Noise Network Intrusion Detection Rules for Security Operations Centers. In ACM Asia Conference on Computer and Communications Security (ASIA CCS ’25), August 25–29, 2025, Hanoi, Vietnam. ACM, New York, NY, USA, 14 pages. [https://doi.org/10.1145/3708821.3710823](https://doi.org/10.1145/3708821.3710823)**

