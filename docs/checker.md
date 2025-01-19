# Writing checkers

## CheckerInterface

In order to write a new checker, you must extend the `suricata_check.checkers.interface.CheckerInterface` and implement the `_check_rule` function, which takes a rule (`idstools.rule.Rule`) as input and returns a collection of issues (`suricata.check.typing.IssuesType`). The most minimal checker, looks as follows:

```python
import idstools.rule
from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils.typing import ISSUES_TYPE


class ExampleChecker(CheckerInterface):
    codes = dict()

    def _check_rule(
        self: "ExampleChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        return issues
```

## Detecting issues

To detect issues, you can use utility functions provided in `suricata_check.utils.checker`. A lot of utility functions exist, and you are encouraged to check out the [Checker API Reference](https://suricata-check.teuwen.net/autoapi/suricata_check/utils/checker/index.html) for a complete overview. For example, it contains utility functions to check whether a Suricata option is (not) set, and enables asserting that atleast one or all option values are (not) equal to a certain value or regular expression.

All you have to do to add new issue types is, to add the desired issue code (e.g. `E000`) to the `codes` field of the class, and append a new `Issue` to the list of `issues` that is returned at the end of `_check_rule` depending on the output of the utlity function called from `suricata_check.utils.checker`. For example, we can add two new issue types as follows:

```python
import logging
import idstools.rule
from suricata_check.checkers.interface import CheckerInterface
from suricata_check.utils import checker
from suricata_check.utils.typing import ISSUES_TYPE, Issue


class ExampleChecker(CheckerInterface):
    codes = {
        "E000": {"severity": logging.INFO},
        "E001": {"severity": logging.INFO},
    }

    def _check_rule(
        self: "ExampleChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if checker.is_rule_option_set(rule, "msg"):
            issues.append(
                Issue(
                    code="E000",
                    message="This rule sets the `msg` field!",
                )
            )

        if checker.is_rule_option_equal_to(rule, "sid", "1234"):
            issues.append(
                Issue(
                    code="E001",
                    message="This rule has sid `1234`, which seems temporary.\nDo not forget to change it to an actual sid!",
                )
            )

        return issues
```

## Using custom checkers

In order to use your newly written checker, you should either install the package as an extension and install it as described in [Releasing checkers as a package](#releasing-checkers-as-a-package) or you need to make use of the API and import your checker as documented in [API Usage](./api_usage.md#selecting-checkers).

## Testing checkers

To make testing of checkers easier, we have provided the `suricata_check.tests.GenericChecker` class that one can inherit in a test suite to write a new checker. The minimal change required is that `__run_around_tests` si implemented to set the `checker` field of the `GenericChecker` class to an instance of the checker being tested.

```python
import logging
import os
import sys

import pytest
from suricata_check.tests import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check_extension_example


class TestExample(GenericChecker):
    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)
        self.checker = suricata_check_extension_example.checkers.ExampleChecker()


def __main__():
    pytest.main()
```

Out of the box, no rules are actually tested but the structure of the codes provided in the `codes` field of the checker are tested.

### Asserting expected issues for rules

Usually, it is desirable to have atleast two tests for each issue type, i.e. one rule for which the issue is present and one rule for which it is not. To write a test, create an `idstools.rule.Rule` object by using `idstools.rule.parse` and pass this rule object to `self._test_issue` while also providing the issue code to check for and a boolean to indicate whether the issue should (not) be raised. The `GenericChecker._test_issue` function will under the hood perform various assertions, in addition to whether the issue is raised or not such as checking whether any undocumented issue codes are emitted, and whether the raised issue has the required metadata to describe the checker that raised the code. For example, to write tests for the two issues we created earlier, we can use the following code:

```python
import logging
import os
import sys

import idstools.rule
import pytest
from suricata_check.tests import GenericChecker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check_extension_example


class TestExample(GenericChecker):
    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)
        self.checker = suricata_check_extension_example.checkers.ExampleChecker()

    def test_e000_bad(self):
        rule = idstools.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:1;)""",
        )

        self._test_issue(rule, "E000", True)

    def test_e000_good(self):
        rule = idstools.rule.parse(
            """alert ip any any -> any any (sid:1;)""",
        )

        self._test_issue(rule, "E000", False)

    def test_e001_bad(self):
        rule = idstools.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:1234;)""",
        )

        self._test_issue(rule, "E001", True)

    def test_e001_good(self):
        rule = idstools.rule.parse(
            """alert ip any any -> any any (msg:"Test"; sid:20101234;)""",
        )

        self._test_issue(rule, "E001", False)


def __main__():
    pytest.main()
```

## Releasing checkers as a package

It is possible to extend `suricata-check` with additional checkers and release them in a seperate package. An example of such an extension is given in the [suricata-check-extension-example](https://github.com/Koen1999/suricata-check-extension-example) project.

Note that for extensions to be automatically discovered by the CLI, their module name should begin with `suricata_check_`, they should expose `suricata_check_extension.__version__`, and their checkers should implement the `CheckerInterface`.
