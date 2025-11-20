---
myst:
    html_meta:
      "description lang=en": "suricata-check offers an extension for integration with Visual Studio Code using the Language Server Protocol"
      "keywords": "Suricata, rules, ruleset, suricata-check, LSP, VSCode, Visual Studio Code, Language Server Protocol, extension, integration, rules, rule"
---
# Visual Studio Code Extension

Instead of using `suricata-check` from the command-line, you can also use the [official Visual Studio Code extension](https://marketplace.visualstudio.com/items?itemName=Koen1999.suricata-check).
The extension offers the same functionality as the command-line and integrates seamlessly with [CI/CD pipelines](./ci_cd.md) if you [configure it through an INI file](./ini.md).

Below you can find an example of how the issued detected by `suricata-check` would be highlighted in Visual Studio Code.

```{figure} static/png/vscode.png
---
class: with-border
---

An overview of the integration of `suricata-check` with Visual Studio Code.
```

## Working with large files or extensions

The `suricata-check` version bundled with the extension comes with minimal dependencies and without [custom checker extensions](./checker.md).

To increase the performance of the extension on large rulesets, and the enable any extension you may have installed in your environment, we suggest to set the `suricata-check.importStrategy` setting in VSCode to `fromEnvironment` and to install `suricata-check` to your environment by running the following command:

```bash
pip install -U suricata-check[performance]
```

Any extensions you have installed in addition, such as the `suricata-check-design-principles` extension, will be discovered automatically when `suricata-check.importStrategy` is set to `fromEnvironment`.
