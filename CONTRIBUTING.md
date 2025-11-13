# Contributing

The `suricata-check` project is actively maintained and welcomes new contributions in the form of issues and PRs. The project maintains quality-standards for the codebase using CI/CD workflows and review processes to ensure the code remains maintainable for current and future contributors.

First time contributors are encouraged to check out [issues labelled as good first issue](https://github.com/Koen1999/suricata-check/labels/good%20first%20issue), which are curated for beginners. These issues do not warrant large or complex changes to a large number of components.

Additionally, the project explicitly welcomes the following types of contributions:

- Improving the overall quality of the codebase (e.g., refining functionality or tests)
- Enhancing CI/CD workflows *(discuss first in an issue)*
- Improving the existing documentation
- [Proposing new features](https://github.com/Koen1999/suricata-check/issues) that are in-line with current project goals *(discuss first in an issue)*

When in doubt whether a contribution is a good fit for the project, you are encouraged to open or comment on an issue so the maintainers can provide clarifications.

If you would like to contribute, below you can find some helpful suggestions and instructions.

## Reporting bugs

To report a bug you encountered, please open an issue in the [issues](https://github.com/Koen1999/suricata-check/issues/new?assignees=Koen1999&labels=bug&projects=&template=%F0%9F%90%9B-bug-report.md&title=%5BBUG%5D) section. You are requested to fill in the entire issue template and to include a minimal example of when the bug occurs, such that we can reproduce the issue.

## Proposing new rule issues

To propose new rule issue, or issue group, we strongly suggest you open a issue in the [issues](https://github.com/Koen1999/suricata-check/issues/new?assignees=&labels=enhancement&projects=&template=%F0%9F%92%A1-new-rule-issue.md&title=%5BNEW+RULE+ISSUE%5D) section first to discuss whether the rule issue should be implemented and how. Please be sure to fill in the entire issue template as it also contributes to the documentation around the proposed rule issue. Importantly, new rule issues should always have test cases describing rules where the issue is present and a similar variant where the issue is mitigated.

## Installing from source

To install `suricata-check` from source (potentially with local modifications), simply run the following commands:

```bash
git clone https://github.com/Koen1999/suricata-check
cd suricata-check
pip install .
pytest
```

## Preparing the development environment

To install packages required for running tests and linting, run the following command:

```bash
pip install pip-tools
pip-compile --all-extras -o requirements-dev.txt pyproject.toml
pip install -U -r requirements-dev.txt
```

Note that you may want to setup a [virtual environment (venv)](https://docs.python.org/3/library/venv.html) before installing dependencies to prevent conflicts.

## Running tests

If you wish to run the majority of the tests whilst skipping the slow integration tests on large third-party rulesets, use the following command:

```bash
pytest
```

To run the slower integration tests at the end of your development cycle, use the following command instead:

```bash
pytest -m "slow" -k "not train"
```

### Inspecting test coverage

Test coverage is automatically assessed when running tests. To inspect the coverage, open `htmlcov/index.html` in your browser and navigate from there.

## Linting

To automatically fix some linting issues and check for remaining issues, run the following commands:

```bash
black .
ruff check . --fix
pyright
```

### Markdownlint

If you made changes to `.md` file and want to lint them locally, you have to install `markdownlint` using `npm`.

```bash
npm install -g markdownlint-cli2
```

Now you can lint markdown files using to automatically detect all issues and fix some:

```bash
markdownlint-cli2 --fix "**/*.md"
```

## Docs

To automatically generate the documentation from the code, run the following commands:

```bash
./docs/make.bat clean
./docs/make.bat html
```

To locally view the docs, run the following command:

```bash
python -m http.server -b localhost -d docs/_build/html 8000
```

and inspect the docs at `localhost:8000`

## Pull requests

When you create a pull request (PR), several checks are automatically run. These include some basic code style checks, as well as running all non-slow tests. PRs that do not pass these checks will not be merged. Additionally, PRs will undergo atleast one round of feedback before merging and require approval of atleast one contributor.

PRs should have a clean commit history and have a singular focus since changelogs are automatically generated from PR names. If your PR introduces new functions or classes, tests and documentation should be included where appropriate.

PRs that satisfy the quality criteria of the project (e.g., pass automated CI/CD workflows) and receive one approving review from a maintainer will be merged as long as they are in-line with the current goals of the project.

## Writing Extensions

It is possible to extend `suricata-check` with additional checkers without contributing these checkers to the main project.
This may be beneficial if your checkers serve a very narrow use-case or if you would like to develop proprietary checkers.
An example of such an extension is given in the [suricata-check-extension-example](https://github.com/Koen1999/suricata-check-extension-example) project.
Note that for extensions to be automatically discovered by the CLI, their module name should begin with `suricata_check_`, they should expose `suricata_check_extension.__version__`, and their checkers should implement the `CheckerInterface`.

### Note on licensing

The `suricata-check` package containing the CLI and `CheckerInterface`, as well as the 'core' checkers contained therein are licensed under the [European Union Public Licence (EUPL)](https://github.com/Koen1999/suricata-check/blob/master/LICENSE), implying that modifications to the source code should be made available when a derivative work is distributed (incl. network use). It should be noted that any extension implementing the `CheckerInterface`, or using utility functions from `suricata-check` is not considered a derivative work and may therefore be distributed under another license not requiring the disclosure of source code. As a result, it is possible to implement proprietary checkers and distribute these without disclosing their source code. For example, the [suricata-check-extension-example](https://github.com/Koen1999/suricata-check-extension-example) module is licensed under the [Apache 2.0 license](https://github.com/Koen1999/suricata-check-extension-example/blob/master/LICENSE), which does not require disclosure of source code for derivative works and permits changing the license for derivative works.
