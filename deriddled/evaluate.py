"""Load evaluation windows and compute flag rates, recall and user-level bootstrap / Wilson CIs."""
import math

import numpy as np
import pandas as pd

from deriddled.config import connect, load_config, path
from deriddled.splits import LABEL_COLUMN, split_case


def load_split(target: str, split: str, columns: list[str], full: bool = True) -> pd.DataFrame:
    cfg = load_config()["data"]
    src = path(cfg["features_dir" if full else "features_sample_dir"]).as_posix()
    cols = ", ".join(dict.fromkeys(["login_id", "ts", "user_id", "country", LABEL_COLUMN[target], *columns]))
    return connect().execute(f"""
        SELECT {cols} FROM (
            SELECT *, {split_case(target)} AS split
            FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true)
        ) WHERE split = '{split}'
    """).df()


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (centre - half, centre + half)


def bootstrap_recall(flags: pd.Series, groups: pd.Series, n_boot: int = 2000, seed: int = 0) -> tuple[float, float]:
    per_group = pd.DataFrame({"g": groups.values, "hit": flags.values.astype(int)}).groupby("g")["hit"].agg(["sum", "count"])
    if per_group.empty:
        return (math.nan, math.nan)
    hits, counts = per_group["sum"].to_numpy(), per_group["count"].to_numpy()
    rng = np.random.default_rng(seed)
    chunk = max(1, 20_000_000 // len(hits))
    recalls = []
    for start in range(0, n_boot, chunk):
        idx = rng.integers(0, len(hits), size=(min(chunk, n_boot - start), len(hits)))
        recalls.append(hits[idx].sum(axis=1) / counts[idx].sum(axis=1))
    return tuple(np.percentile(np.concatenate(recalls), [2.5, 97.5]))


def top_rate_flags(score: pd.Series, rate: float, seed: int = 0) -> pd.Series:
    k = int(round(rate * len(score)))
    jitter = np.random.default_rng(seed).random(len(score))
    order = np.lexsort((jitter, -score.to_numpy()))
    flags = np.zeros(len(score), dtype=bool)
    flags[order[:k]] = True
    return pd.Series(flags, index=score.index)


def recall_at_rates(df: pd.DataFrame, score: pd.Series, label: str, rates=(0.005, 0.01, 0.02), n_boot: int = 2000) -> list[dict]:
    return [{"rate": r, **flag_metrics(df, top_rate_flags(score, r), label, n_boot)} for r in rates]


def flag_metrics(df: pd.DataFrame, flags: pd.Series, label: str, n_boot: int = 2000) -> dict:
    y = df[label].astype(bool).to_numpy()
    f = flags.astype(bool).to_numpy()
    tp, pos = int((f & y).sum()), int(y.sum())
    lo, hi = bootstrap_recall(flags[y], df.loc[y, "user_id"], n_boot)
    w_lo, w_hi = wilson(tp, pos)
    return {
        "logins": len(df),
        "challenge_rate": f.mean(),
        "legit_challenge_rate": f[~y].mean() if (~y).any() else math.nan,
        "positives": pos,
        "flagged": int(f.sum()),
        "caught": tp,
        "recall": tp / pos if pos else math.nan,
        "precision": tp / f.sum() if f.any() else math.nan,
        "recall_ci_user_bootstrap": (lo, hi),
        "recall_ci_wilson": (w_lo, w_hi),
    }
