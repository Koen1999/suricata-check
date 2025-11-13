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

## GitHub

Integration with GitHub is easy. All you need to do is checkout the repository containing the rules that require checking, setup a Python environment and install `suricata-check`, and run it with the `--github` option to automatically issue the required GitHub workflow commands for integration.

For example, when integrated with GitHub, issues can be highlighted in a pull requests (PRs) similar to [this example PR](https://github.com/Koen1999/suricata-check-action/pull/1/files).

For GitHub, you can copy [this workflow](https://github.com/Koen1999/suricata-check-action/blob/main/.github/workflows/suricata-check.yml) and modify it to your needs.

```yaml
name: Suricata Check

on:
  pull_request:
    branches: ["main"]
  push:
    branches: ["main"]
concurrency:
  group: ${{ github.ref }}
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
          python -m pip install --upgrade pip
          python -m pip install "suricata-check[performance]>=0.3.0beta0"

      - name: Test with suricata-check
        run: |
          suricata-check --github --issue-severity=WARNING
```

## GitLab

To integrate `suricata-check` with GitLab, you need to run it in a workflow with the `--gitlab` option to produce the `suricata-check-gitlab.json` file which follows the required [CodeClimate report / GitLab Code Quality Report format](https://docs.gitlab.com/ee/ci/testing/code_quality.html#code-quality-report-format).

To have GitLab process this output, you need to declare the code quality report using the syntax prescribed by [GitLab](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportscodequality).
