"""Cumulative feature-group ablation (FR-4.4): user → +population → +graph → +likelihood → +anomaly → +reputation."""
import time

import joblib
import pandas as pd
import xgboost as xgb

from deriddled.anomaly import add_scores
from deriddled.config import load_config, path
from deriddled.evaluate import recall_at_rates
from deriddled.train import EXCLUDE, NEG_FRAC, RATES, REPUTATION, load, matrix, segments
from deriddled.splits import LABEL_COLUMN

GROUPS = {
    "user behaviour": ["hour", "weekday", "rtt_present", "user_prior_logins", "user_prior_successes",
                       "secs_since_prev", "secs_since_prev_success", "user_logins_1m", "user_logins_1h",
                       "user_fails_1h", "user_logins_24h", "user_fails_24h", "user_fail_ratio_24h",
                       "new_country", "new_asn", "new_device", "new_ip", "new_subnet24", "device_type"],
    "+ population": ["asn_freq", "country_freq", "ua_freq", "asn_attack_rate", "asn_fail_rate",
                     "ip_prior_logins", "ip_prior_attack_ip", "ip_prior_fails"],
    "+ graph": ["ip_logins_24h", "ip_users_24h", "ip_fails_24h", "subnet_logins_24h", "subnet_users_24h", "asn_users_24h"],
    "+ likelihood score": ["lr_score"],
    "+ anomaly": ["anomaly_score", "novelty_count"],
    "+ reputation": REPUTATION,
}


def fit_cols(train: pd.DataFrame, label: str, cols: list[str]):
    X = matrix(train, cols)
    model = xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=3, min_child_weight=5, subsample=0.8, colsample_bytree=0.8,
        tree_method="hist", enable_categorical=True, max_cat_to_onehot=8, random_state=0, n_jobs=-1)
    model.fit(X, train[label].astype(int), sample_weight=train["weight"])
    return model, {c: list(X[c].cat.categories) for c in X.columns if str(X[c].dtype) == "category"}


def run() -> pd.DataFrame:
    forest = joblib.load(path(load_config()["data"]["models_dir"]) / "isolation_forest.joblib")
    rows, t0 = [], time.time()
    for target in ("ato", "attack_ip"):
        label = LABEL_COLUMN[target]
        train = add_scores(load(target, "train", "full", NEG_FRAC), forest)
        valid = add_scores(load(target, "valid"), forest)
        cols = []
        for step, group in GROUPS.items():
            if target == "attack_ip" and step == "+ reputation":
                continue
            cols = cols + [c for c in group if c not in EXCLUDE[target]]
            model, cats = fit_cols(train, label, cols)
            score = pd.Series(model.predict(matrix(valid, cols, cats), output_margin=True), index=valid.index)
            for seg, part in segments(valid, target).items():
                for m in recall_at_rates(part, score.loc[part.index], label, RATES[target]):
                    rows.append({"target": target, "step": step, "n_features": len(cols), "segment": seg, **m})
            print(f"[{target}] {step:20s} {len(cols):2d} features ({time.time() - t0:.0f}s)", flush=True)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    res = run()
    pd.set_option("display.width", 250)
    pd.set_option("display.max_rows", 300)
    keep = ((res.target == "ato") & res.rate.isin([0.005, 0.01])) | ((res.target == "attack_ip") & res.rate.isin([0.05, 0.10]))
    cols = ["target", "step", "n_features", "segment", "rate", "positives", "caught", "recall", "precision", "recall_ci_wilson"]
    print(res.loc[keep, cols].to_string(index=False))
