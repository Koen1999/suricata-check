import logging
import os
import sys

import idstools.rule
import numpy
import pandas
import pytest
import sklearn.metrics
import suricata_check.checkers.principle

from ..checker import GenericChecker
from .test_principle import NON_LABELLED_PUBLIC_RULES_PATH
from .test_principle import RULES as P_RULES

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import suricata_check

CHECKER_CLASS = suricata_check.checkers.PrincipleMLChecker

RULES = P_RULES.copy()
for rule in P_RULES.keys():
    RULES[rule]["should_raise"] = [
        code.replace("P00", "Q00") for code in RULES[rule]["should_raise"]
    ]
    RULES[rule]["should_not_raise"] = [
        code.replace("P00", "Q00") for code in RULES[rule]["should_not_raise"]
    ]

_logger = logging.getLogger(__name__)


class TestPrincipleML(GenericChecker):
    @pytest.fixture(autouse=True)
    def __run_around_tests(self):
        logging.basicConfig(level=logging.DEBUG)
        self.checker = CHECKER_CLASS()

    @pytest.mark.slow()
    def test_train_principle_ml(self):
        self._set_log_level(logging.INFO)

        if not os.path.exists(NON_LABELLED_PUBLIC_RULES_PATH):
            pytest.skip("Cannot access non-public test data")

        principle_rules = pandas.read_csv(NON_LABELLED_PUBLIC_RULES_PATH)
        assert isinstance(self.checker, CHECKER_CLASS)
        self.checker.train(principle_rules)

    @pytest.mark.parametrize(
        ("code", "expected", "raw_rule"),
        [
            (code, True, raw_rule)
            for code in CHECKER_CLASS.codes
            for raw_rule, expected in RULES.items()
            if code in expected["should_raise"]
        ],
    )
    @pytest.hookimpl(trylast=True)
    def test_rule_bad(self, code, expected, raw_rule):
        if code not in RULES[raw_rule]["should_raise"]:
            # Silently skip and succeed the test
            return

        rule = idstools.rule.parse(raw_rule)

        # fail is false, so we do permit False Negatives
        self._test_issue(rule, code, expected, fail=False)

    @pytest.mark.parametrize(
        ("code", "expected", "raw_rule"),
        [
            (code, False, raw_rule)
            for code in CHECKER_CLASS.codes
            for raw_rule, expected in RULES.items()
            if code in expected["should_not_raise"]
        ],
    )
    @pytest.hookimpl(trylast=True)
    def test_rule_good(self, code, expected, raw_rule):
        rule = idstools.rule.parse(raw_rule)

        # fail is true, so we do not permit False Positives
        self._test_issue(rule, code, expected, fail=False)

    @pytest.hookimpl(trylast=True)
    @pytest.mark.slow()
    def test_precision_recall(self):
        self._set_log_level(logging.INFO)

        if not os.path.exists(NON_LABELLED_PUBLIC_RULES_PATH):
            pytest.skip("Cannot access non-public test data")

        assert isinstance(self.checker, CHECKER_CLASS)

        principle_rules = pandas.read_csv(NON_LABELLED_PUBLIC_RULES_PATH)
        principle_rules["group"] = principle_rules["rule.rule"].apply(
            lambda x: suricata_check.utils.checker.get_rule_suboption(
                idstools.rule.parse(x), "metadata", "mitre_technique_id"
            )
        )

        for group in principle_rules["group"].unique():
            if group is None:
                continue

            _logger.info("Testing PrincipleMLChecker by leaving out group %s", group)

            principle_rules_train: pandas.DataFrame = principle_rules[principle_rules["group"] != group]  # type: ignore reportAssignmentType
            principle_rules_test: pandas.DataFrame = principle_rules[principle_rules["group"] == group]  # type: ignore reportAssignmentType

            self.checker.train(principle_rules_train, reuse_models=True)

            for code, test_col in (
                ("Q000", "labelled.no_proxy"),
                ("Q001", "labelled.success"),
                ("Q002", "labelled.thresholded"),
                ("Q003", "labelled.exceptions"),
                ("Q004", "labelled.generalized_match_content"),
                ("Q005", "labelled.generalized_match_location"),
            ):
                y_pred_list = []
                for rule in principle_rules_test["rule.rule"]:
                    parsed_rule = idstools.rule.parse(rule)
                    y_pred_list.append(self.check_issue(parsed_rule, code, True)[0])

                y_true = numpy.array(principle_rules_test[test_col].to_numpy() == 0)
                y_pred = numpy.array(y_pred_list)

                precision = float(
                    sklearn.metrics.precision_score(y_true, y_pred, zero_division=0)  # type: ignore reportArgumentType
                )
                recall = float(
                    sklearn.metrics.recall_score(y_true, y_pred, zero_division=1)  # type: ignore reportArgumentType
                )

                fp_mask = ~y_true & y_pred
                fn_mask = y_true & ~y_pred

                for rule in principle_rules_test.loc[fp_mask, "rule.rule"]:
                    _logger.debug(
                        "Code {} False Positive: {}".format(code, rule)  # noqa: G001
                    )

                for rule in principle_rules_test.loc[fn_mask, "rule.rule"]:
                    _logger.debug(
                        "Code {} False Negative: {}".format(code, rule)  # noqa: G001
                    )

                _logger.info(
                    "Code {}\tPrecision: {}\tRecall: {}".format(  # noqa: G001
                        code, precision, recall
                    )
                )


def __main__():
    pytest.main()
