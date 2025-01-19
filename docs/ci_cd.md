---
myst:
    html_meta:
        "description lang=en": "suricata-check is a command line utility to provide feedback on Suricata rules to by detecting issues through static analysis."
        "keywords": "Suricata, rules, ruleset, suricata-check, Continuous Integration, Continuous Deployment, Workflow, Action, GitHub, GitLab, CodeClimate"
---
# CI/CD Integration

If you maintain a large rulebase in through version-control managed platform, you may be interested in integrating `suricata-check` with your Continuous Integration and Continuous Deployment workflows.

This is possible using the `--github` and `--gitlab` CLI options. The integration can be further adjusted to the specific deployment environment needs using [the other available CLI options](./cli_usage.md).

An example of such an integration for GitHub can be found [here](https://github.com/Koen1999/suricata-check-action).

## GitHub

Integration with GitHub is easy. All you need to do is checkout the repository containing the rules that require checking, setup a Python environment and install `suricata-check`, and run it with the `--github` option to automatically issue the required GitHub workflow commands for integration.

For example, when integrated with GitHub, issues can be highlighted in a pull requests (PRs) similar to [this example PR](https://github.com/Koen1999/suricata-check-action/pull/1/files).

For GitHub, you can copy [this workflow](https://github.com/Koen1999/suricata-check-action/blob/main/.github/workflows/suricata-check.yml) and modify it to your needs.

## GitLab

To integrate `suricata-check` with GitLab, you need to run it in a workflow with the `--gitlab` option to produce the `suricata-check-gitlab.json` file which follows the required [CodeClimate report / GitLab Code Quality Report format](https://docs.gitlab.com/ee/ci/testing/code_quality.html#code-quality-report-format).

To have GitLab process this output, you need to declare the code quality report using the syntax prescribed by [GitLab](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportscodequality).
