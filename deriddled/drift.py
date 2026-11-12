"""Monthly PSI for the main model's top features and score, plus weekly challenge rates vs validation (label-free monitoring)."""
import json

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import xgboost as xgb

from deriddled.config import ROOT, connect, load_config, path
from deriddled.likelihood import log_lr

REFERENCE = ("2020-02-03", "2020-08-01")
VALIDATION = ("2020-08-01", "2020-10-01")
SAMPLE_PER_MONTH = 150_000
EPS = 1e-4


def psi(expected: np.ndarray, actual: np.ndarray, edges: np.ndarray) -> float:
    def shares(x):
        x = np.asarray(x, dtype=float)
        nan = np.isnan(x)
        counts = np.histogram(x[~nan], bins=edges)[0]
        return np.append(counts, nan.sum()) / len(x)
    e, a = np.clip(shares(expected), EPS, None), np.clip(shares(actual), EPS, None)
    return float(np.sum((a - e) * np.log(a / e)))


def edges_for(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    q = np.unique(np.nanquantile(x, np.linspace(0, 1, 11)))
    if len(q) < 2:
        q = np.array([q[0] - 0.5, q[0] + 0.5])
    q[0], q[-1] = -np.inf, np.inf
    return q


def load_month(con, month: str) -> pd.DataFrame:
    cfg = load_config()["data"]
    df = con.execute(f"""
        SELECT f.*, l.* EXCLUDE (login_id), r.* EXCLUDE (login_id)
        FROM read_parquet('{path(cfg['features_dir']).as_posix()}/**/*.parquet', hive_partitioning = true) f
        JOIN read_parquet('{path(cfg['likelihood_dir']).as_posix()}/*.parquet') l USING (login_id)
        JOIN read_parquet('{path(cfg['reputation_dir']).as_posix()}/*.parquet') r USING (login_id)
        WHERE f.month = '{month}'
    """).df()
    df["lr_score"] = log_lr(df, "attack_informed", 1.0, ("ip", "asn", "country", "ua"))
    return df


def run() -> None:
    cfg = load_config()
    models = path(cfg["data"]["models_dir"])
    name = cfg["models"]["ato"]
    meta = json.loads((models / f"{name}_meta.json").read_text())
    cal = json.loads((models / f"{name}_calibration.json").read_text())
    booster = xgb.Booster()
    booster.load_model(models / f"{name}.json")
    gain = pd.Series(booster.get_score(importance_type="gain")).sort_values(ascending=False)
    top = [f for f in gain.index if f != "device_type"][:10]
    device = pd.CategoricalDtype(meta["categories"]["device_type"])

    con = connect()
    months = [r[0] for r in con.execute(
        f"SELECT DISTINCT month FROM read_parquet('{path(cfg['data']['features_dir']).as_posix()}/**/*.parquet', "
        f"hive_partitioning = true) ORDER BY 1").fetchall()]
    samples, weekly = {}, []
    for month in months:
        df = load_month(con, month)
        X = df[meta["features"]].copy()
        for c in X.columns:
            if X[c].dtype == bool:
                X[c] = X[c].astype(int)
        X["device_type"] = pd.Categorical(X["device_type"].astype(object).where(X["device_type"].notna()), dtype=device)
        df["margin"] = booster.predict(xgb.DMatrix(X, enable_categorical=True), output_margin=True)
        p = np.interp(df["margin"], cal["margin_grid"], cal["p_grid"])
        df["flag"] = p >= cal["t_challenge"]
        weekly.append(df.groupby(df.ts.dt.to_period("W").dt.start_time).agg(logins=("flag", "size"), flagged=("flag", "sum")))
        samples[month] = df[top + ["margin", "ts"]].sample(min(SAMPLE_PER_MONTH, len(df)), random_state=0)
        print(f"{month}: {len(df):,} logins scored, challenge-or-block rate {df.flag.mean():.4%}", flush=True)

    allrows = pd.concat(samples.values())
    ref = allrows[(allrows.ts >= REFERENCE[0]) & (allrows.ts < REFERENCE[1])]
    table = {}
    for col in top + ["margin"]:
        edges = edges_for(ref[col])
        table[col] = {m: psi(ref[col], s[col], edges) for m, s in samples.items()}
    psi_df = pd.DataFrame(table).T
    weeks = pd.concat(weekly).groupby(level=0).sum()
    weeks["rate"] = weeks.flagged / weeks.logins
    v = weeks[(weeks.index >= VALIDATION[0]) & (weeks.index < VALIDATION[1])]
    v_rate = v.flagged.sum() / v.logins.sum()
    weeks["vs_validation"] = weeks.rate / v_rate - 1
    weeks["flag_50pct"] = weeks.vs_validation.abs() > 0.5

    pd.set_option("display.width", 250)
    print("\nPSI vs reference (Feb-Jul 2020); > 0.2 flags drift:")
    print(psi_df.round(3).to_string())
    print(f"\nfeatures/months over 0.2: {int((psi_df > 0.2).sum().sum())}")
    print(f"\nvalidation challenge-or-block rate: {v_rate:.4%}")
    print(weeks.assign(rate=weeks.rate.map("{:.4%}".format), vs_validation=weeks.vs_validation.map("{:+.0%}".format))
          [["logins", "flagged", "rate", "vs_validation", "flag_50pct"]].to_string())

    out = ROOT / "docs" / "figures"
    out.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(9, 3.6), facecolor="#fcfcfb")
    ax.set_facecolor("#fcfcfb")
    ax.plot(weeks.index, weeks.rate * 100, color="#2a78d6", linewidth=2)
    ax.axhline(v_rate * 100, color="#898781", linestyle="--", linewidth=1)
    ax.fill_between(weeks.index, v_rate * 50, v_rate * 150, color="#e1e0d9", alpha=0.5, linewidth=0)
    ax.annotate("validation level ± 50%", (weeks.index[1], v_rate * 150), fontsize=8.5, color="#52514e",
                xytext=(0, 4), textcoords="offset points")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="y", color="#e1e0d9", linewidth=0.6)
    ax.set_ylabel("% of logins challenged or blocked", color="#52514e")
    ax.set_ylim(bottom=0)
    ax.set_title("Weekly challenge-or-block rate, main ATO model", loc="left", fontweight="bold")
    fig.tight_layout()
    fig.savefig(out / "weekly_challenge_rate.png", dpi=130)
    psi_df.round(4).to_csv(path(cfg["data"]["models_dir"]).parent / "ops" / "psi_by_month.csv")
    print(f"\nfigure: {out / 'weekly_challenge_rate.png'}")


if __name__ == "__main__":
    run()
