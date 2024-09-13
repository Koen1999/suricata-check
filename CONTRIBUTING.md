# Contributing

If you would like to contribute, below you can find some helpful suggestions and instructions.

## Reporting bugs

To report a bug you encountered, please open an issue in the [issues](https://github.com/Koen1999/suricata-check/issues/new?assignees=Koen1999&labels=bug&projects=&template=%F0%9F%90%9B-bug-report.md&title=%5BBUG%5D) section. You are requested to fill in the entire issue template and to include a minimal example of when the bug occurs, such that we can reproduce the issue.

## Proposing new rule issues

To propose new rule issue, or issue group, we strongly suggest you open a issue in the [issues](https://github.com/Koen1999/suricata-check/issues/new?assignees=&labels=enhancement&projects=&template=%F0%9F%92%A1-new-rule-issue.md&title=%5BNEW+RULE+ISSUE%5D) section first to discuss whether the rule issue should be implemented and how. Please be sure to fill in the entire issue template as it also contributes to the documentation around the proposed rule issue. Importantly, new rule issues should always have test cases describing rules where the issue is present and a similar variant where the issue is mitigated.

## Preparing the development environment

To install packages required for running tests and linting, run the following command:

```bash
pip install -r requirements.txt
```

## Running tests

If you wish to run the majority of the tests whilst skipping the slow integration tests on large third-party rulesets, use the following command:

```bash
pytest
```

To run the slower integration tests at the end of your development cycle, use the following command instead:

```bash
pytest -m "slow" -k "not train"
```

## Training new models

To run the train new ML models (i.e., `PrincipleMLChecker`) at the end of your development cycle in case you modified this pipeline, delete the `.pkl` files corresponding to the saved model(s) and run the following command:

```bash
pytest -m "slow" -k "train" --cov-fail-under=0
```

## Linting

To automatically fix some linting issues and check for remaining issues, run the following commands:

```bash
black .
ruff check . --fix
pyright
```

## Pull requests

When you create a pull request (PR), several checks are automatically run. These include some basic code style checks, as well as running all non-slow tests. PRs that do not pass these checks will not be merged. Additionally, PRs will undergo atleast one round of feedback before merging and require approval of atleast one contributor.
