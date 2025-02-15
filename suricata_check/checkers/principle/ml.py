"""`PrincipleMLChecker`."""

import copy
import logging
import os
import pickle
from collections import Counter
from collections.abc import Iterable
from typing import Any, Literal, Optional, Union, overload

import idstools.rule
import xgboost
from pandas import DataFrame, Series
from sklearn.metrics import f1_score, make_scorer, precision_score, recall_score
from sklearn.model_selection import (
    GridSearchCV,
    RepeatedStratifiedKFold,
    cross_val_score,
)
from sklearn.pipeline import Pipeline

from suricata_check._version import SURICATA_CHECK_DIR
from suricata_check.checkers.interface.checker import CheckerInterface
from suricata_check.checkers.principle._utils import get_message
from suricata_check.utils.checker import get_rule_option, get_rule_suboptions
from suricata_check.utils.checker_typing import ISSUES_TYPE, Issue

_PICKLE_PATH = os.path.join(SURICATA_CHECK_DIR, "data", "principle_ml_checker.pkl")
N_JOBS = 8


_logger = logging.getLogger(__name__)


COUNT_COLUMNS = (
    "flowbits.isset.count",
    "flowbits.isntoset.count",
    "flowint.isset.count",
    "flowint.isntoset.count",
    "xbits.isset.count",
    "xbits.uisnotset.count",
    "http.uri.count",
    "http.method.count",
    "dns.query.count",
    "content.count",
    "pcre.count",
    "startswith.count",
    "bsize.count",
    "depth.count",
    "urilen.count",
    "flow.from_server.count",
    "flow.to_server.count",
    "flow.from_client.count",
    "flow.to_client.count",
)
STRING_COLUMNS = ()
DROPDOWN_COLUMNS = (
    "proto",
    "threshold.type",
)
NUMERICAL_COLUMNS = ("threshold.count",)
SPLITTABLE_FEATURES = (
    "metadata",
    "flow",
    "threshold",
)
MSG_KEYWORDS = ("Suspicious", "CVE", "Vulnerability", "Response")
MSG_COLUMNS = ("msg.contains." + keyword for keyword in MSG_KEYWORDS)
IP_KEYWORDS = ("$HOME_NET", "$HTTP_SERVERS", "$EXTERNAL_NET", "any")
IP_COLUMNS = tuple(
    ["source_addr.contains." + keyword for keyword in IP_KEYWORDS]
    + ["dest_addr.contains." + keyword for keyword in IP_KEYWORDS]
)


PIPELINE = Pipeline(
    [
        (
            "classify",
            xgboost.XGBClassifier(),
        )
    ]
)
# https://shengyg.github.io/repository/machine%20learning/2017/02/25/Complete-Guide-to-Parameter-Tuning-xgboost.html
PARAM_GRID: list[dict] = [
    {
        # Fixed parameters for problem / desired complexity
        "classify__n_estimators": [1000],
        "classify__objective": ["binary:logistic"],
        ###
        # Parameters to optimize
        ## Learning rate
        "classify__eta": [0.01, 0.1, 0.3],
        ## Tree parameters
        "classify__subsample": [1.0],
        "classify__colsample_bytree": [0.25, 0.5, 0.75, 1.0],
        "classify__scale_pos_weight": [0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 10.0],
        "classify__max_depth": [1, 3],
        "classify__min_child_weight": [1],
        "classify__gamma": [0, 0.1],
        ## Regularization
        "classify__lambda": [0, 0.01, 0.1],
        "classify__alpha": [0, 0.01, 0.1],
    },
]

PRECISION_WEIGHT = 10
SCORER = make_scorer(
    lambda y, y_pred: (PRECISION_WEIGHT + 1)
    / (
        PRECISION_WEIGHT / (precision_score(y, y_pred, zero_division=1) + 1e-10)  # type: ignore reportArgumentType
        + 1 / (recall_score(y, y_pred, zero_division=0) + 1e-10)  # type: ignore reportArgumentType
    )
)
SPLITTER = RepeatedStratifiedKFold(n_splits=2, n_repeats=10)
GRIDSEARCHCV = GridSearchCV(
    PIPELINE, PARAM_GRID, cv=SPLITTER, scoring=SCORER, error_score="raise", n_jobs=N_JOBS, verbose=1  # type: ignore reportArgumentType
)


class PrincipleMLChecker(CheckerInterface):
    """The `PrincipleChecker` contains several checks based on the Ruling the Unruly paper and target specificity and coverage.

    Codes Q000-Q009 report on non-adherence to rule design principles similar to Q000-Q009.
    Differently, they are the result of machine learning analysis of the rules.
    """

    count_columns = COUNT_COLUMNS
    string_columns = STRING_COLUMNS
    dropdown_columns = DROPDOWN_COLUMNS
    numerical_columns = NUMERICAL_COLUMNS
    splittable_features = SPLITTABLE_FEATURES
    msg_keywords = MSG_KEYWORDS
    msg_columns = MSG_COLUMNS
    ip_keywords = IP_KEYWORDS
    ip_columns = IP_COLUMNS

    codes = {
        "Q000": {"severity": logging.INFO},
        "Q001": {"severity": logging.INFO},
        "Q002": {"severity": logging.INFO},
        "Q003": {"severity": logging.INFO},
        "Q004": {"severity": logging.INFO},
        "Q005": {"severity": logging.INFO},
    }

    enabled_by_default = (
        False  # Since the checker is relatively slow, it is disabled by default
    )

    _dtypes: Optional[dict[str, Any]] = None
    _models: dict[str, Pipeline] = {}

    def __new__(
        cls: type["PrincipleMLChecker"],
        filepath: Optional[str] = _PICKLE_PATH,
        *args: tuple,
        **kwargs: dict,
    ) -> "PrincipleMLChecker":
        """Returns a new or unpickled instance of the class."""
        if filepath:
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    inst = pickle.load(f)

                # BEGIN LEGACY CODE
                # CAN BE REMOVED AFTER TRAINING NEW PKL
                if hasattr(inst, "models"):
                    inst._models = inst.models  # noqa: SLF001
                    inst._dtypes = inst.dtypes  # noqa: SLF001
                # END LEGACY CODE

                if not inst.__class__.__name__ == cls.__name__:
                    _logger.error("Unpickled object is not of type %s", cls)
                    inst = super().__new__(cls, *args, **kwargs)  # type: ignore reportargumentType
                elif (
                    not hasattr(inst, "_models")
                    or len(
                        inst._models  # noqa: SLF001 type: ignore reportAttributeAccess
                    )
                    == 0
                ):
                    _logger.error("Unpickled object does not have trained models")
                    inst = super().__new__(cls, *args, **kwargs)  # type: ignore reportargumentType
                else:
                    if "include" in kwargs:
                        inst.include = kwargs["include"]
                    _logger.info("Unpickled object with trained models successfully")
            else:
                _logger.warning("No model found for PrincipleMLChecker at %s", filepath)
                inst = super().__new__(cls, *args, **kwargs)  # type: ignore reportargumentType
        else:
            inst = super().__new__(cls, *args, **kwargs)  # type: ignore reportargumentType

        return inst

    def __getnewargs__(
        self: "PrincipleMLChecker",
    ) -> tuple:
        """Returns the arguments to be passed to the __new__ method when unpickling."""
        return (None,)

    def _check_rule(
        self: "PrincipleMLChecker",
        rule: idstools.rule.Rule,
    ) -> ISSUES_TYPE:
        issues: ISSUES_TYPE = []

        if len(self._models) == 0:
            return issues

        for code, model in self._models.items():
            if model.predict(self._get_features(rule, True))[0]:
                issues.append(
                    Issue(
                        code=code,
                        message=get_message(code),
                    )
                )

        return issues

    def train(  # noqa: C901
        self: "PrincipleMLChecker",
        df: DataFrame,
        rule_col: str = "rule.rule",
        principle_cols: dict[str, str] = {
            "Q000": "labelled.no_proxy",
            "Q001": "labelled.success",
            "Q002": "labelled.thresholded",
            "Q003": "labelled.exceptions",
            "Q004": "labelled.generalized_match_content",
            "Q005": "labelled.generalized_match_location",
        },
        reuse_models: bool = False,
    ) -> None:
        """Train several models for the checker to detect issues in rules.

        The checker class with trained models is stored in a pickle file (`_PICKLE_PATH`).
        """
        self._dtypes = None
        if not reuse_models:
            self._models = {}

        # Extract features and determine feature dtypes
        X_train = self._get_train_df(df[rule_col])  # noqa: N806

        for col in X_train.columns:
            try:
                X_train[col].var()
                _logger.debug("Detected column: %s", col)
            except:
                _logger.error("Error with column %s", col)
                _logger.error(X_train[col])
                raise

        # # Drop zero variance columns
        X_train = X_train.drop(  # noqa: N806
            X_train.columns[(X_train.fillna(-1337).var(axis=0) <= 0)].to_list(),  # type: ignore reportAttributeAccessIssue
            axis=1,
        )

        # Drop columns with too few occurrences of possible values
        for col in X_train.columns:
            if (
                not col.endswith(".count")
                and not col.endswith(".num")
                and not col.endswith(".len")
            ):
                if X_train[col].value_counts().min() <= 1:
                    X_train = X_train.drop(  # noqa: N806
                        [col],
                        axis=1,
                    )

        for col in X_train.columns:
            try:
                X_train[col].var()
                _logger.info("Using column: %s", col)
            except:
                _logger.error("Error with column %s", col)
                _logger.error(X_train[col])
                raise

        # Store used features and their dtypes
        self._dtypes = X_train.dtypes.to_dict()
        _logger.debug(self._dtypes)

        # Redo feature extraction now that FE parameters are set
        X_train = self._get_train_df(df[rule_col])  # noqa: N806

        _logger.info(
            "Training model with features: [%s]",
            ", ".join([str(x) for x in X_train.columns]),
        )

        _logger.info(X_train)

        for code, col in principle_cols.items():
            y_true = df[col].to_numpy() == 0

            if not reuse_models or code not in self._models:
                # Train new model with grid search to find optimal parameters
                gridsearchcv: GridSearchCV = copy.deepcopy(GRIDSEARCHCV)

                gridsearchcv.fit(X_train, y_true)

                _logger.info("Code %s params: %s", code, gridsearchcv.best_params_)
                _logger.info(
                    "Code %s Weighted F1-score: %s", code, gridsearchcv.best_score_
                )

                self._models[code] = gridsearchcv.best_estimator_

            precision = cross_val_score(
                self._models[code],
                X_train,
                y_true,
                scoring=make_scorer(precision_score, zero_division=0.0),
                cv=SPLITTER,
                n_jobs=N_JOBS,
            ).mean()
            recall = cross_val_score(
                self._models[code],
                X_train,
                y_true,
                scoring=make_scorer(recall_score, zero_division=0.0),
                cv=SPLITTER,
                n_jobs=N_JOBS,
            ).mean()
            f1 = cross_val_score(
                self._models[code],
                X_train,
                y_true,
                scoring=make_scorer(f1_score, zero_division=0.0),
                cv=SPLITTER,
                n_jobs=N_JOBS,
            ).mean()
            _logger.info("Code %s Precision score: %s", code, precision)
            _logger.info("Code %s Recall score: %s", code, recall)
            _logger.info("Code %s F1-score: %s", code, f1)

            # Refit model with training data.
            self._models[code].fit(X_train, y_true)

        pickle.dump(self, open(_PICKLE_PATH, "wb"))

    def _get_train_df(self: "PrincipleMLChecker", rules: Iterable[str]) -> DataFrame:
        feature_vectors = []
        for rule in rules:
            parsed_rule = idstools.rule.parse(rule)
            assert parsed_rule is not None
            feature_vectors.append(self._get_features(parsed_rule, False))

        return DataFrame(feature_vectors)

    def _get_raw_features(  # noqa: C901
        self: "PrincipleMLChecker", rule: idstools.rule.Rule
    ) -> Series:
        d: dict[str, Optional[Union[str, int]]] = {
            "proto": get_rule_option(rule, "proto")
        }

        options = rule["options"]

        for option in options:
            d[option["name"]] = option["value"]

        counter = Counter([option["name"] for option in options])
        for option, count in counter.items():
            d[option + ".count"] = count

        for option in options:
            if option["name"] not in self.splittable_features:
                continue

            suboptions = [
                {"name": k, "value": v}
                for k, v in get_rule_suboptions(rule, option["name"], warn=False)
            ]

            if len(suboptions) == 0:
                continue

            for suboption in suboptions:
                d[option["name"] + "." + suboption["name"]] = suboption["value"]

            counter = Counter([suboption["name"] for suboption in suboptions])
            for suboption, count in counter.items():
                d[option["name"] + "." + suboption + ".count"] = count

        msg = get_rule_option(rule, "msg")
        assert msg is not None
        msg = msg.lower()
        for col, keyword in zip(self.msg_columns, self.msg_keywords):
            d[col] = keyword.lower() in msg

        source_addr = get_rule_option(rule, "source_addr")
        assert source_addr is not None
        source_addr = source_addr.lower()
        for keyword in self.ip_keywords:
            col = "source_addr.contains." + keyword
            d[col] = keyword.lower() in source_addr

        dest_addr = get_rule_option(rule, "dest_addr")
        assert dest_addr is not None
        dest_addr = dest_addr.lower()
        for keyword in self.ip_keywords:
            col = "dest_addr.contains." + keyword
            d[col] = keyword.lower() in dest_addr

        return Series(d)

    def _preprocess_features(self: "PrincipleMLChecker", data: Series) -> Series:
        original_cols: set[str] = set(data.index)

        for col in self.string_columns:
            if col not in data:
                continue
            data[col + ".len"] = len(data[col])
            data = data.drop(col)

        for col in self.dropdown_columns:
            if col not in data:
                continue
            data[col + "." + data[col] + ".bool"] = 1
            data = data.drop(col)

        for col in self.numerical_columns:
            if col not in data:
                continue
            data[col + ".num"] = float(data[col])
            data = data.drop(col)

        remaining_cols = (
            original_cols
            - set(self.count_columns)
            - set(self.string_columns)
            - set(self.dropdown_columns)
            - set(self.numerical_columns)
            - set(self.msg_columns)
            - set(self.ip_columns)
        )

        for col in remaining_cols:
            data = data.drop(col)

        return data

    @overload
    def _get_features(
        self: "PrincipleMLChecker", rule: idstools.rule.Rule, frame: Literal[True]
    ) -> DataFrame:
        pass

    @overload
    def _get_features(
        self: "PrincipleMLChecker", rule: idstools.rule.Rule, frame: Literal[False]
    ) -> Series:
        pass

    def _get_features_frame(self: "PrincipleMLChecker", features: Series) -> DataFrame:
        features_frame = features.to_frame().transpose()

        if self._dtypes is None:
            return features_frame

        for col, dtype in self._dtypes.items():
            if features_frame.dtypes[col] != dtype:
                features_frame[col] = features_frame[col].astype(dtype)

        return features_frame

    def _get_features(
        self: "PrincipleMLChecker", rule: idstools.rule.Rule, frame: bool
    ) -> Union[Series, DataFrame]:
        features: Series = self._get_raw_features(rule)
        features = self._preprocess_features(features)

        features["custom.negated.count"] = rule["raw"].count(':!"')

        if self._dtypes is None:
            return features

        for col, dtype in self._dtypes.items():
            if col not in features:
                if col.endswith(".count"):
                    features[col] = 0
                elif col.endswith(".bool"):
                    features[col] = 0
                elif col.endswith(".num"):
                    features[col] = -1
                else:
                    _logger.error(
                        "Unsure how to handle missing feature %s of type %s",
                        col,
                        dtype,
                    )

        features = features[list(self._dtypes.keys())]  # type: ignore reportAssignmentType

        if not frame:
            return features

        return self._get_features_frame(features)
