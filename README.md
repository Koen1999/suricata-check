# suricata-check

[![Python Version](https://img.shields.io/pypi/pyversions/suricata-check)](https://www.python.org)
[![PyPi](https://img.shields.io/pypi/status/suricata-check)](https://pypi.python.org/pypi/suricata-check)
[![GitHub License](https://img.shields.io/github/license/Koen1999/suricata-check)](https://github.com/Koen1999/suricata-check/blob/master/LICENSE)

[![Python Lint](https://github.com/Koen1999/suricata-check/actions/workflows/python-lint.yml/badge.svg)](https://github.com/Koen1999/suricata-check/actions/workflows/python-lint.yml)
[![Python Pytest](https://github.com/Koen1999/suricata-check/actions/workflows/python-pytest.yml/badge.svg)](https://github.com/Koen1999/suricata-check/actions/workflows/python-pytest.yml)
[![Python Build](https://github.com/Koen1999/suricata-check/actions/workflows/python-build.yml/badge.svg)](https://github.com/Koen1999/suricata-check/actions/workflows/python-build.yml)
[![Python Publish](https://github.com/Koen1999/suricata-check/actions/workflows/python-publish.yml/badge.svg)](https://github.com/Koen1999/suricata-check/actions/workflows/python-publish.yml)

`suricata-check` is a command line utility to provide feedback on [Suricata](https://github.com/OISF/suricata) rules.
The tool can detect various issues including those covering syntax validity, interpretability, rule specificity, rule coverage, and efficiency.

## Installation

### From PyPi

To install `suricata-check` from [PyPi](https://pypi.org/project/suricata-check/), simply run the following command:

```bash
pip install suricata-check[performance]
```

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
Usage: suricata-check [OPTIONS]

  Processes all rules inside a rules file and outputs a list of issues found.

  Args: ---- out: A path to a directory where the output will be written.
  rules: A path to a Suricata rules file or a directory in which a single rule
  file can be discovered single_rule: A single Suricata rule to be checked. If
  set, the rules file will be ignored. log_level: The verbosity level for
  logging. evaluate_disabled: A flag indicating whether disabled rules should
  be evaluated.

  Raises: ------   BadParameter: If provided arguments are invalid.
  RuntimeError: If no checkers could be automatically discovered.

Options:
  -o, --out TEXT               Path to suricata-check output folder.
                               [default: .]
  -r, --rules TEXT             Path to Suricata rules to provide check on.
                               [default: .]
  -s, --single-rule TEXT       A single Suricata rule to be checked
  --log-level TEXT             Verbosity level for logging. Can be one of
                               ('DEBUG', 'INFO', 'WARNING', 'ERROR')
                               [default: INFO]
  --evaluate-disabled BOOLEAN  Flag to evaluate disabled rules.  [default:
                               False]
  --help                       Show this message and exit.
```

Usage of suricata-check as a module is currently not documented in detail, but the type hints and docstrings in the code should provide a decent start.

## Output

The output of `suricata-check` is collected in a folder and spread across several files. Additionally, the most important output is visible in the terminal.

`suricata-check.log` contains log messages describing the executing flow of `suricata-check` and can be useful during development, as well as to detect potential issues with parsing rules or rule files.

`suricata-check.fast` contains a condensed overview of all issues found by `suricata-check` and is useful during rule engineering as feedback points to further improve rules under development.

`suricata-check.jsonl` is a jsonlines log file containing all the issues presented in `suricata-check.fast` together with parsed versions of _all_ rules and is useful for programatically further processing output of `suricata-check`.

## Issue codes

`suricata-check` employs various checkers, each emitting one or more _issue codes_.
The issue codes are grouped into several ranges, depending on the category of the checker.
Each issue group is explained in detail below.
For details regarding specific issues, we recommend you check the message of the issue as well as the test example rules under `tests/checkers`.

### Overview

| Issue identifier format | Column 2                                                    |
| ----------------------- | ----------------------------------------------------------- |
| M000                    | Rules pertaining to the detection of valid Suricata syntax. |
| S000                    | Rules derived from the Suricata Style Guide.                |
| P000                    | Rules based [Ruling the Unruly]().                          |
| C000                    | Rules based on community issues, such as this GitHub.  |

### Mandatory issues

Rules starting with prefix _M_ indicate issues pertaining to the validity of Suricata rules.
Rules with _M_-type issues will most probably not be used by Suricata due to invalid syntax or missing fields.

Not all invalid rules wlll be reported through _M_-type issues as some rules can simply not be parsed to the point where these issues are detected.
Instead, you can detect these rules through the `ERROR` messages in `suricata-check.log`.

### Suricata Style Guide issues

Rules starting with prefix _S_ indicate issues pertaining to the adherence to the [Suricata Style Guide](https://github.com/sidallocation/suricata-style-guide).
Rules with _S_-type issues are likely to hint on interpretability or efficiency issues.

### Principle issues

Rules starting with prefix _P_ indicate issues relating to rule design principles posed in the [Ruling the Unruly]() paper.
Rules with _P_-type issues can relate to a specificity and coverage.

### Community issues

Rules starting with prefix _C_ indicate issues posed by the community and are an extension on top of the other issue groups.
Rules with _C_-type issues can relate to a wide variety of issues.
You can propose your own community type issues that should be checked for in the [issues](https://github.com/Koen1999/suricata-check/issues) section.

## Contributing

If you would like to contribute, below you can find some helpful suggestions and instructions.

### Reporting bugs

To report a bug you encountered, please open an issue in the [issues](https://github.com/Koen1999/suricata-check/issues) section. You are requested to fill in the entire issue template and to include a minimal example of when the bug occurs, such that we can reproduce the issue.

### Proposing new rule issues

To propose new rule issue, or issue group, we strongly suggest you open a issue in the [issues](https://github.com/Koen1999/suricata-check/issues) section first to discuss whether the rule issue should be implemented and how. Please be sure to fill in the entire issue template as it also contributes to the documentation around the proposed rule issue. Importantly, new rule issues should always have test cases describing rules where the issue is present and a similar variant where the issue is mitigated.

### Preparing the development environment

To install packages required for running tests and linting, run the following command:

```bash
pip install -r requirements.txt
```

### Running tests

If you wish to run the majority of the tests whilst skipping the slow integration tests on large third-party rulesets, use the following command:

```bash
pytest
```

To run the slower integration tests at the end of your development cycle, use the following command instead:

```bash
pytest -m "slow"
```

### Linting

To automatically fix some linting issues and check for remaining issues, run the following commands:

```bash
black .
ruff check . --fix
```

### Pull requests

When you create a pull request (PR), several checks are automatically run. These include some basic code style checks, as well as running all non-slow tests. PRs that do not pass these checks will not be merged. Additionally, PRs will undergo atleast one round of feedback before merging and require approval of atleast one contributor.

## License

This project is licensed under the [European Union Public Licence (EUPL)](https://github.com/Koen1999/suricata-check/blob/master/LICENSE).
