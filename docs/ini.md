---
myst:
    html_meta:
      "description lang=en": "suricata-check is a command line utility to provide feedback on Suricata rules to by detecting issues through static analysis."
      "keywords": "Suricata, rules, ruleset, suricata-check, CLI, Command Line, rules, rule, ini"
---
# Configuration using `suricata-check.ini`

The CLI options mentioned in [CLI Reference](./cli.rst) can also be configured using a `.ini` file.This is recommended when working on shared projects or when integrating with [CI/CD](./ci_cd.md) to encourage consistent usage of `suricata-check`.

The default `.ini` is called `suricata-check.ini` and should be located in the project directory or common working directory. If the default name and location are used, the configuration will be automatically discovered when you run `suricata-check`.

The contents of `suricata-check.ini` can be configured as follows:
```ini
[suricata-check]
issue-severity="INFO"
include-all=true
exclude=["P.*", "Q.*"]
```

If you use a non-standard name or location for your `.ini` file, you can manually specify the path as a command-line argument:

```bash
suricata-check --ini /path/to/my.ini
```

Any configuration options passed to `suricata-check` via the CLI will take precedence over options specified in a `.ini` configuration file.
