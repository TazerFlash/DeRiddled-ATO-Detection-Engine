"""Build point-in-time likelihood counts and score logins with the Freeman et al. likelihood-ratio baseline."""
import shutil
import sys
import time

import numpy as np
import pandas as pd

from deriddled.config import ROOT, connect, load_config, path
from deriddled.evaluate import recall_at_rates
from deriddled.splits import LABEL_COLUMN, split_case

FEATURES = ("ip", "asn", "country", "ua")
SOURCES = {"sample": ("sample_dir", "likelihood_sample_dir", "features_sample_dir"),
           "full": ("logins_dir", "likelihood_dir", "features_dir")}


def build(which: str) -> None:
    cfg = load_config()["data"]
    src_key, out_key, _ = SOURCES[which]
    out_dir = path(cfg[out_key])
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    sql = (ROOT / "sql" / "likelihood.sql").read_text(encoding="utf-8")
    sql = sql.replace("{source}", f"{path(cfg[src_key]).as_posix()}/**/*.parquet")
    t0 = time.time()
    connect().execute(f"COPY ({sql}) TO '{(out_dir / 'likelihood.parquet').as_posix()}' (FORMAT parquet, COMPRESSION zstd)")
    print(f"{which} likelihood counts written to {out_dir} in {time.time() - t0:.0f}s")


def load(target: str, split: str, which: str = "full") -> pd.DataFrame:
    cfg = load_config()["data"]
    _, lik_key, feat_key = SOURCES[which]
    feats = path(cfg[feat_key]).as_posix()
    lik = path(cfg[lik_key]).as_posix()
    return connect().execute(f"""
        SELECT f.login_id, f.ts, f.user_id, f.country, f.{LABEL_COLUMN[target]}, l.* EXCLUDE (login_id)
        FROM (SELECT *, {split_case(target)} AS split
              FROM read_parquet('{feats}/**/*.parquet', hive_partitioning = true)) f
        JOIN read_parquet('{lik}/*.parquet') l USING (login_id)
        WHERE f.split = '{split}'
    """).df()


def log_lr(df: pd.DataFrame, variant: str = "freeman", beta: float = 5.0, features=FEATURES) -> pd.Series:
    total = np.zeros(len(df))
    for f in features:
        vocab = df[f"{f}_vocab"].to_numpy(float)
        p_pop = (df[f"{f}_pop"].to_numpy(float) + 1) / (df["global_n"].to_numpy(float) + vocab + 1)
        p_user = (df[f"{f}_user"].to_numpy(float) + beta * p_pop) / (df["user_n"].to_numpy(float) + beta)
        if variant == "freeman":
            p_attack = p_pop
        else:
            p_attack = (df[f"{f}_attack"].to_numpy(float) + 1) / (df["global_attack"].to_numpy(float) + vocab + 1)
        total += np.log(p_attack) - np.log(p_user)
    return pd.Series(total, index=df.index)


def evaluate(split: str = "valid", which: str = "full", betas=(1.0, 5.0, 20.0)) -> pd.DataFrame:
    camp = load_config()["rule_baseline"]["ato_campaign_country"]
    configs = {
        "ato": [("freeman", FEATURES), ("attack_informed", FEATURES)],
        "attack_ip": [("freeman", FEATURES), ("attack_informed", ("asn", "country", "ua"))],
    }
    rows = []
    for target, variants in configs.items():
        label = LABEL_COLUMN[target]
        df = load(target, split, which)
        segments = {"all": df}
        if target == "ato":
            in_camp = df["country"] == camp
            segments |= {"campaign": in_camp | ~df[label], "other": ~in_camp | ~df[label]}
            segments = {k: (v if k == "all" else df[v]) for k, v in segments.items()}
        for variant, feats in variants:
            for beta in betas:
                for seg, part in segments.items():
                    score = log_lr(part, variant, beta, feats)
                    for m in recall_at_rates(part, score, label):
                        rows.append({"target": target, "variant": variant, "features": "+".join(feats),
                                     "beta": beta, "segment": seg, **m})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "evaluate"
    which = sys.argv[2] if len(sys.argv) > 2 else "full"
    if cmd == "build":
        build(which)
    else:
        out = evaluate("valid", which)
        pd.set_option("display.width", 250)
        pd.set_option("display.max_columns", 20)
        pd.set_option("display.max_rows", 500)
        cols = ["target", "variant", "features", "beta", "segment", "rate", "challenge_rate",
                "positives", "caught", "recall", "recall_ci_wilson"]
        print(out[cols].to_string(index=False))
