---
myst:
    html_meta:
        "description lang=en": "suricata-check can be easily integrated into CI/CD pipelines of GitHub, GitLab and others to continously check Suricata rules for quality issues."
        "keywords": "Suricata, rules, ruleset, suricata-check, Continuous Integration, Continuous Deployment, Workflow, Action, GitHub, GitLab, CodeClimate"
---
# CI/CD Integration

If you maintain a large rulebase in through version-control managed platform, you may be interested in integrating `suricata-check` with your Continuous Integration and Continuous Deployment workflows.

This is possible using the `--github` and `--gitlab` CLI options. The integration can be further adjusted to the specific deployment environment needs using [the other available CLI options](./cli_usage.md).

An example of such an integration for GitHub is available in the [`suricata-check-action` repository](https://github.com/Koen1999/suricata-check-action).

## Passing CLI options using an INI file

When integrating `suricata-check` into a project, it is recommended to configure suricata-check using a `.ini` file as documented on the [documentation page dedicated to configuration using the INI file](./ini.md). By doing so, all collaborators to the project will adhere to the same quality standards and CI/CD linting outcomes will be in-line with local linting outcomes.

## GitHub

Integration with GitHub is easy. All you need to do is checkout the repository containing the rules that require checking, setup a Python environment and install `suricata-check`, and run it with the `--github` option to automatically issue the required GitHub workflow commands for integration.

For example, when integrated with GitHub, issues can be highlighted in a pull requests (PRs) similar to [this example PR](https://github.com/Koen1999/suricata-check-action/pull/1/files).

For GitHub, you can copy [this workflow](https://github.com/Koen1999/suricata-check-action/blob/main/.github/workflows/suricata-check.yml) and modify it to your needs.

```yaml
name: Suricata Check

on:
  pull_request:
    branches: ["main", "master"]
  push:
    branches: ["main", "master"]
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}

jobs:
  suricata-check:
    name: Suricata Check
    runs-on: ubuntu-latest

    strategy:
      fail-fast: true

    steps:
      - uses: actions/checkout@v5

      - name: Set up Python
        uses: actions/setup-python@v6

      - name: Install dependencies
        run: |
          python -m pip install --upgrade --upgrade-strategy eager pip
          python -m pip install suricata-check[performance]

      - name: Test with suricata-check
        run: |
          suricata-check --github
```

Below you can find an example of how the issued detected by `suricata-check` would be highlighted in GitHub.

```{figure} static/png/workflow.png
---
class: with-border
---

Example GitHub workflow where issues with Suricata rules are highlighted.
```

## GitLab

To integrate `suricata-check` with GitLab, you need to run it in a workflow with the `--gitlab` option to produce the `suricata-check-gitlab.json` file which follows the required [CodeClimate report / GitLab Code Quality Report format](https://docs.gitlab.com/ee/ci/testing/code_quality.html#code-quality-report-format).

To have GitLab process this output, you need to declare the code quality report using the syntax prescribed by [GitLab](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportscodequality).
