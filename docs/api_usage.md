---
myst:
    html_meta:
        "description lang=en": "suricata-check offers an API that exposes more functionality than the CLI and makes it easy to extend upon the existing functionalities."
        "keywords": "Suricata, rules, ruleset, suricata-check, API, Python"
---
# API Usage

Sometimes it may be more convenient to avoid the CLI and instead use the module directly, which exposes more functionality and may be easier te extend if your project also uses Python. Below, we will characterize several use-cases you may encounter and how to address them using the functionality exposed by {py:obj}`suricata_check`.

All publicly exposed modules, classes, and methods are documented and typed such that IDEs such as Visual Studio Code will provide useful information and suggestions as you write code using {py:obj}`suricata_check`.

## Analyze a single rule

In order to analyze a single rule using the module, you first need to parse the rule with {py:obj}`suricata_check`.
Thereafter, you can process it using {py:obj}`suricata_check.analyze_rule` as follows to obtain a {py:obj}`suricata_check.utils.checker_typing.RuleReport`

```python
import suricata_check

rule = """\
alert ip any any -> any any (msg:"Some msg"; sid:1;)"""
parsed_rule = suricata_check.utils.rule.parse(rule)
assert parsed_rule is not None

rule_report = suricata_check.analyze_rule(parsed_rule)
```

Note that if a rule is unparseable, `parsed_rule` may be `None` or {py:obj}`suricata_check.utils.rule.parse` may throw a {py:obj}`suricata_check.utils.rule.ParsingError`. Parseable rules need not be valid Suricata rules. If {py:obj}`suricata_check.utils.rule.parse` cannot parse the rule, a {py:obj}`suricata_check.utils.checker_typing.InvalidRuleError` will be raised.

You can further inspect the rule report, which is implemented as a dataclass, by treating it as a dictionary.

```python
print(rule_report.rule['raw'])

print("Number of issues found: " + str(len(rule_report.issues)))

```

## Inspecting issues

Similar to the rule report, issues are represented by dataclasses, which you can treat as dictionaries.

```python
print(rule_report.rule['raw'])

for issue in rule_report.issues:
    print(issue.code)
    print(issue.msg)

```

## Selecting checkers

Sometimes you may only be interested in running a single checker, or enabling/disabling certain codes similar to the CLI usage. You can do so by passing checkers to {py:obj}`suricata_check.analyze_rule`.

```python
checkers = suricata_check.get_checkers(include=("M.*",), exclude=tuple())

rule_report = suricata_check.analyze_rule(parsed_rule, checkers=checkers)
```

If you have implemented a checker implementing the `CheckerInterface` as descibed in [CONTRIBUTING](./contributing.md), the checker will be discoverable by the {py:obj}`suricata_check.get_checkers` function. Any other class (e.g. `MyOwnChecker`) implementing {py:obj}`suricata_check.checkers.interface.CheckerInterface`, may be passed to {py:obj}`suricata_check.analyze_rule` directly as follows:

```python
rule_report = suricata_check.analyze_rule(parsed_rule, checkers=[MyOwnChecker()])
```

## Processing rulesets

Similar to the CLI, it is possible to process entire rulesets at once using {py:obj}`suricata_check.process_rules_file`. Also for this function, it is optionally possible to explcitly pass checkers to use.

```python
from suricata_check.checkers import MetadataChecker

ruleset_report = suricata_check.process_rules_file(
    "/var/lib/suricata/rules/suricata.rules", 
    evaluate_disabled=True, 
    checkers=[MetadataChecker()]
)

for rule_report in ruleset_report.rules:
    has_issues = len(rule_report.issues) > 0
    if has_issues:
        print(rule_report.rule['raw'])
```
