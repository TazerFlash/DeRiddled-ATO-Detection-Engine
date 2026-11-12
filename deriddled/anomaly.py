"""Label-free anomaly layer: Isolation Forest on behaviour features plus a per-user novelty count, evaluated alone and inside XGBoost."""
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from deriddled.config import load_config, path
from deriddled.evaluate import recall_at_rates
from deriddled.train import NEG_FRAC, RATES, fit, load, matrix, segments

NOVELTY = ["new_country", "new_asn", "new_device", "new_ip", "new_subnet24"]
LOG_COUNTS = ["user_prior_logins", "user_prior_successes", "secs_since_prev", "secs_since_prev_success",
              "user_logins_1h", "user_logins_24h", "user_fails_24h", "ip_prior_logins", "ip_logins_24h",
              "ip_users_24h", "ip_fails_24h", "subnet_logins_24h", "subnet_users_24h", "asn_users_24h"]
FREQS = ["asn_freq", "country_freq", "ua_freq"]
FIT_ROWS = 200_000


def prep(df: pd.DataFrame) -> np.ndarray:
    cols = [df[c].astype(float) for c in NOVELTY + ["rtt_present"]]
    cols += [np.log1p(df[c].astype(float).fillna(-1).clip(lower=-1) + 1) for c in LOG_COUNTS]
    cols += [np.log10(df[c].astype(float) + 1e-7) for c in FREQS]
    cols += [df["user_fail_ratio_24h"].fillna(0), df["hour"].astype(float)]
    return np.column_stack(cols)


def add_scores(df: pd.DataFrame, forest: IsolationForest) -> pd.DataFrame:
    df["anomaly_score"] = -forest.score_samples(prep(df))
    df["novelty_count"] = df[NOVELTY].astype(int).sum(axis=1)
    return df


def fit_forest(target: str = "ato", seed: int = 0) -> IsolationForest:
    train = load(target, "train", "full", NEG_FRAC)
    sample = train.sample(min(FIT_ROWS, len(train)), random_state=seed)
    forest = IsolationForest(n_estimators=200, max_samples=256, random_state=seed, n_jobs=-1).fit(prep(sample))
    out = path(load_config()["data"]["models_dir"])
    joblib.dump(forest, out / "isolation_forest.joblib")
    return forest


def run() -> None:
    t0 = time.time()
    forest = fit_forest()
    print(f"isolation forest fitted in {time.time() - t0:.0f}s", flush=True)
    pd.set_option("display.width", 250)
    pd.set_option("display.max_rows", 200)
    rows = []
    for target in ("ato", "attack_ip"):
        label = "is_ato" if target == "ato" else "is_attack_ip"
        valid = add_scores(load(target, "valid"), forest)
        print(f"[{target}] scored validation in {time.time() - t0:.0f}s", flush=True)
        for name in ("anomaly_score", "novelty_count"):
            for seg, part in segments(valid, target).items():
                for m in recall_at_rates(part, part[name], label, RATES[target]):
                    rows.append({"target": target, "model": name, "segment": seg, **m})

        if target == "ato":
            train = add_scores(load(target, "train", "full", NEG_FRAC), forest)
            for name, extra in (("reputation", []), ("reputation + anomaly", ["anomaly_score", "novelty_count"])):
                model, cols, cats = fit_with_extra(train, extra) if extra else fit(train, target, "reputation", 3, 1.0)
                score = pd.Series(model.predict(matrix(valid, cols, cats), output_margin=True), index=valid.index)
                for seg, part in segments(valid, target).items():
                    for m in recall_at_rates(part, score.loc[part.index], label, RATES[target]):
                        rows.append({"target": target, "model": name, "segment": seg, **m})
            print(f"[ato] xgboost comparison done in {time.time() - t0:.0f}s", flush=True)

    res = pd.DataFrame(rows)
    cols = ["target", "model", "segment", "rate", "positives", "caught", "recall", "precision", "recall_ci_wilson"]
    print(res[cols].to_string(index=False))


def fit_with_extra(train: pd.DataFrame, extra: list[str]):
    import xgboost as xgb
    from deriddled.train import feature_list
    cols = feature_list("ato", "reputation") + extra
    X = matrix(train, cols)
    model = xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=3, min_child_weight=5, subsample=0.8, colsample_bytree=0.8,
        tree_method="hist", enable_categorical=True, max_cat_to_onehot=8, scale_pos_weight=1.0,
        eval_metric="aucpr", random_state=0, n_jobs=-1)
    model.fit(X, train["is_ato"].astype(int), sample_weight=train["weight"])
    cats = {c: list(X[c].cat.categories) for c in X.columns if str(X[c].dtype) == "category"}
    return model, cols, cats


if __name__ == "__main__":
    run()
