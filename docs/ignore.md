---
myst:
    html_meta:
      "description lang=en": "suricata-check is a command line utility to provide feedback on Suricata rules to by detecting issues through static analysis."
      "keywords": "Suricata, rules, ruleset, suricata-check, CLI, Command Line, rules, rule, ini"
---
# Suppressing rule issues

In addition to the `include` and `exclude` options mentioned in the [CLI Reference](./cli.rst), which are used to enable and disable checkers for entire rules files, you can also suppress issues on for individual rules using `type: ignore` comments.

For example, if you consider a certain issue (e.g., `S800`) to be a false positive or if its something you do not want to focus on currently, you can disable a specific issue code as follows:

```text
alert ip any any -> any any (msg:"Test";)  # suricata-check: ignore S800
```

You can suppress multiple issues by seperating them using commas:

```text
alert ip any any -> any any (msg:"Test";)  # suricata-check: ignore S800,S100,C100
```

You can also use regular expressions to suppress issues:

```text
alert ip any any -> any any (msg:"Test";)  # suricata-check: ignore S800,S.*,C.*
```

Ignoring issues for specific rules as described above will result in output without any of the suppressed issues for that rule. Therefore, these issues will not be present in `stdout`, `suricata-check.fast`, `suricata-check.jsonl` and not reflected in `suricata-check.stats`.