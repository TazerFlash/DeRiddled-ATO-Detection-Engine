"""Train XGBoost ATO / attack-IP models on the time split, compare feature sets on validation, and save models."""
import itertools
import json
import sys
import time

import numpy as np
import pandas as pd
import xgboost as xgb

from deriddled.config import connect, load_config, path
from deriddled.evaluate import recall_at_rates
from deriddled import novelty_ok
from deriddled.likelihood import SOURCES, log_lr
from deriddled.splits import LABEL_COLUMN, split_case

BEHAVIOUR = [
    "hour", "weekday", "rtt_present",
    "user_prior_logins", "user_prior_successes", "secs_since_prev", "secs_since_prev_success",
    "user_logins_1m", "user_logins_1h", "user_fails_1h", "user_logins_24h", "user_fails_24h", "user_fail_ratio_24h",
    "new_country", "new_asn", "new_device", "new_ip", "new_subnet24",
    "asn_freq", "country_freq", "ua_freq", "asn_attack_rate", "asn_fail_rate",
    "ip_prior_logins", "ip_prior_attack_ip", "ip_prior_fails",
    "ip_logins_24h", "ip_users_24h", "ip_fails_24h", "subnet_logins_24h", "subnet_users_24h", "asn_users_24h",
    "lr_score",
]
REPUTATION = ["asn_ato_prior", "asn_ato_rate", "country_ato_prior", "country_ato_rate",
              "ip_ato_prior", "ip_ato_rate", "subnet_ato_prior", "subnet_ato_rate"]
COUNTRY_FEATURES = {"country_ato_prior", "country_ato_rate", "country_freq"}
TAKEOVER_HISTORY = ("asn_ato_prior", "asn_ato_rate", "ip_ato_prior", "ip_ato_rate", "subnet_ato_prior", "subnet_ato_rate")
CATEGORICAL = {"behaviour": ["device_type"], "identity": ["device_type", "country", "asn"], "reputation": ["device_type"],
               "main": ["device_type"], "main_ok": ["device_type"]}
EXCLUDE = {"ato": set(), "attack_ip": {"ip_prior_attack_ip"}}
LR_FEATURES = {"ato": ("ip", "asn", "country", "ua"), "attack_ip": ("asn", "country", "ua")}
NEG_FRAC = 0.15
RATES = {"ato": (0.005, 0.01, 0.02), "attack_ip": (0.01, 0.05, 0.10, 0.20)}
SELECT_RATE = {"ato": 0.01, "attack_ip": 0.10}


def load(target: str, split: str, which: str = "full", neg_frac: float | None = None, rep_dir=None,
         ids: list[int] | None = None) -> pd.DataFrame:
    cfg = load_config()["data"]
    _, lik_key, feat_key = SOURCES[which]
    label = LABEL_COLUMN[target]
    keep = "TRUE" if neg_frac is None else f"({label} OR md5_number(f.login_id::VARCHAR) % 1000 < {int(neg_frac * 1000)})"
    if ids is not None:
        keep += f" AND f.login_id IN ({', '.join(str(int(i)) for i in ids) or 'NULL'})"
    rep_dir = rep_dir or path(cfg["reputation_dir" if which == "full" else "reputation_sample_dir"])
    rep_join = f"LEFT JOIN read_parquet('{rep_dir.as_posix()}/*.parquet') r USING (login_id)" if rep_dir.exists() else ""
    rep_cols = ", r.* EXCLUDE (login_id)" if rep_join else ""
    ok_dir = novelty_ok.out_dir(which)
    ok_join = f"LEFT JOIN read_parquet('{ok_dir.as_posix()}/*.parquet') o USING (login_id)" if ok_dir.exists() else ""
    ok_cols = ", o.* EXCLUDE (login_id)" if ok_join else ""
    df = connect().execute(f"""
        SELECT f.*, l.* EXCLUDE (login_id){rep_cols}{ok_cols}
        FROM (SELECT *, {split_case(target)} AS split
              FROM read_parquet('{path(cfg[feat_key]).as_posix()}/**/*.parquet', hive_partitioning = true)) f
        JOIN read_parquet('{path(cfg[lik_key]).as_posix()}/*.parquet') l USING (login_id)
        {rep_join}
        {ok_join}
        WHERE f.split = '{split}' AND {keep}
        ORDER BY f.login_id
    """).df()
    df["lr_score"] = log_lr(df, "attack_informed", 1.0, LR_FEATURES[target])
    if ok_join:
        df = novelty_ok.derive(df, LR_FEATURES[target])
    df["weight"] = np.where(df[label] | (neg_frac is None), 1.0, 1.0 / (neg_frac or 1.0))
    for c in ("device_type", "country", "asn"):
        df[c] = df[c].astype(str).astype("category")
    return df


def feature_list(target: str, feature_set: str) -> list[str]:
    extra = REPUTATION if feature_set in ("reputation", "main", "main_ok") else []
    drop = EXCLUDE[target] | (COUNTRY_FEATURES if feature_set in ("main", "main_ok") else set())
    cols = [c for c in BEHAVIOUR + extra if c not in drop]
    if feature_set == "main_ok":
        cols = [novelty_ok.SWAP.get(c, c) for c in cols]
    return cols + CATEGORICAL[feature_set]


def matrix(df: pd.DataFrame, cols: list[str], categories: dict | None = None) -> pd.DataFrame:
    X = df[cols].copy()
    for c in X.columns:
        if X[c].dtype == bool:
            X[c] = X[c].astype(int)
    if categories:
        for c, cats in categories.items():
            if c in X:
                values = X[c].astype(str)
                X[c] = pd.Categorical(values.where(values.isin(cats)), categories=cats)
    return X


def fit(train: pd.DataFrame, target: str, feature_set: str, depth: int, spw: float, seed: int = 0,
        monotone: tuple = ()):
    cols = feature_list(target, feature_set)
    X = matrix(train, cols)
    constraints = {c: 1 for c in monotone if c in cols}
    model = xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=depth, min_child_weight=5,
        subsample=0.8, colsample_bytree=0.8, tree_method="hist", enable_categorical=True,
        max_cat_to_onehot=8, scale_pos_weight=spw, eval_metric="aucpr", random_state=seed, n_jobs=-1,
        monotone_constraints=constraints or None,
    )
    model.fit(X, train[LABEL_COLUMN[target]].astype(int), sample_weight=train["weight"])
    categories = {c: list(X[c].cat.categories) for c in X.columns if str(X[c].dtype) == "category"}
    return model, cols, categories


def segments(df: pd.DataFrame, target: str) -> dict[str, pd.DataFrame]:
    if target != "ato":
        return {"all": df}
    label = LABEL_COLUMN[target]
    camp = df["country"].astype(str) == load_config()["rule_baseline"]["ato_campaign_country"]
    return {"all": df, "campaign": df[camp | ~df[label]], "other": df[~camp | ~df[label]]}


def run_grid(target: str, which: str = "full", n_boot: int = 2000) -> pd.DataFrame:
    t0 = time.time()
    train = load(target, "train", which, NEG_FRAC)
    valid = load(target, "valid", which)
    label = LABEL_COLUMN[target]
    print(f"[{target}] train {len(train):,} rows ({int(train[label].sum())} pos), "
          f"valid {len(valid):,} rows ({int(valid[label].sum())} pos), loaded in {time.time() - t0:.0f}s", flush=True)

    rows, best = [], None
    for feature_set, depth, spw in itertools.product(("behaviour", "identity"), (3, 6), (1.0, 20.0)):
        t = time.time()
        model, cols, cats = fit(train, target, feature_set, depth, spw)
        score = pd.Series(model.predict(matrix(valid, cols, cats), output_margin=True), index=valid.index)
        for seg, part in segments(valid, target).items():
            for m in recall_at_rates(part, score.loc[part.index], label, RATES[target], n_boot=n_boot):
                rows.append({"target": target, "features": feature_set, "depth": depth, "spw": spw, "segment": seg, **m})
        r1 = next(r["recall"] for r in rows[::-1] if r["segment"] == "all" and r["rate"] == SELECT_RATE[target]
                  and r["features"] == feature_set and r["depth"] == depth and r["spw"] == spw)
        print(f"  {feature_set:9s} depth={depth} spw={spw:>4} recall@{SELECT_RATE[target]:.0%}={r1:.4f} "
              f"({time.time() - t:.0f}s)", flush=True)
        if best is None or r1 > best[0]:
            best = (r1, feature_set, depth, spw, model, cols, cats)

    _, feature_set, depth, spw, model, cols, cats = best
    out = path(load_config()["data"]["models_dir"])
    out.mkdir(parents=True, exist_ok=True)
    model.save_model(out / f"{target}_xgb.json")
    (out / f"{target}_xgb_meta.json").write_text(json.dumps(
        {"features": cols, "categories": cats, "feature_set": feature_set, "depth": depth, "spw": spw}, indent=2))
    importance = pd.Series(model.get_booster().get_score(importance_type="gain")).sort_values(ascending=False)
    print(f"[{target}] best: {feature_set} depth={depth} spw={spw}\n  top gain:\n{importance.head(12).round(1).to_string()}", flush=True)
    return pd.DataFrame(rows)


def compare_ato(which: str = "full", n_boot: int = 2000) -> pd.DataFrame:
    train = load("ato", "train", which, NEG_FRAC)
    valid = load("ato", "valid", which)
    candidates = {"behaviour": ("behaviour", 3, 1.0), "identity": ("identity", 3, 20.0),
                  "reputation": ("reputation", 3, 1.0), "reputation_spw20": ("reputation", 3, 20.0)}
    scores, rows = {}, []
    for name, (feature_set, depth, spw) in candidates.items():
        model, cols, cats = fit(train, "ato", feature_set, depth, spw)
        scores[name] = pd.Series(model.predict(matrix(valid, cols, cats), output_margin=True), index=valid.index)
        if name == "reputation":
            importance = pd.Series(model.get_booster().get_score(importance_type="gain")).sort_values(ascending=False)
            print(f"reputation top gain:\n{importance.head(12).round(1).to_string()}", flush=True)
            out = path(load_config()["data"]["models_dir"])
            model.save_model(out / "ato_xgb_reputation.json")
            (out / "ato_xgb_reputation_meta.json").write_text(json.dumps(
                {"features": cols, "categories": cats, "feature_set": feature_set, "depth": depth, "spw": spw}, indent=2))
    scores["ensemble"] = (scores["behaviour"].rank(pct=True) + scores["identity"].rank(pct=True)) / 2
    for name, score in scores.items():
        for seg, part in segments(valid, "ato").items():
            for m in recall_at_rates(part, score.loc[part.index], "is_ato", n_boot=n_boot):
                rows.append({"model": name, "segment": seg, **m})
    return pd.DataFrame(rows)


def save(model, name: str, cols: list[str], cats: dict, feature_set: str, depth: int, spw: float, monotone: tuple = ()) -> None:
    out = path(load_config()["data"]["models_dir"])
    out.mkdir(parents=True, exist_ok=True)
    model.save_model(out / f"{name}.json")
    (out / f"{name}_meta.json").write_text(json.dumps(
        {"features": cols, "categories": cats, "feature_set": feature_set, "depth": depth, "spw": spw,
         "monotone_increasing": [c for c in monotone if c in cols]}, indent=2))


def train_and_save(target: str, feature_set: str, depth: int, spw: float, which: str = "full", name: str | None = None,
                   monotone: tuple = ()) -> None:
    name = name or f"{target}_xgb"
    train = load(target, "train", which, NEG_FRAC)
    model, cols, cats = fit(train, target, feature_set, depth, spw, monotone=monotone)
    save(model, name, cols, cats, feature_set, depth, spw, monotone)
    print(f"saved {name}.json ({feature_set}, depth={depth}, spw={spw}, {len(cols)} features)")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "full"
    if len(sys.argv) > 2 and sys.argv[2] == "save":
        train_and_save(sys.argv[3], sys.argv[4], int(sys.argv[5]), float(sys.argv[6]), which,
                       sys.argv[7] if len(sys.argv) > 7 else None)
        sys.exit()
    if len(sys.argv) > 2 and sys.argv[2] == "compare":
        pd.set_option("display.width", 250)
        pd.set_option("display.max_rows", 500)
        res = compare_ato(which)
        print(res[["model", "segment", "rate", "positives", "caught", "recall", "recall_ci_wilson"]].to_string(index=False))
        sys.exit()
    targets = sys.argv[2:] or ["ato", "attack_ip"]
    pd.set_option("display.width", 250)
    pd.set_option("display.max_rows", 500)
    for target in targets:
        res = run_grid(target, which)
        cols = ["features", "depth", "spw", "segment", "rate", "positives", "flagged", "caught", "recall", "precision", "recall_ci_wilson"]
        print(res[cols].to_string(index=False), flush=True)
