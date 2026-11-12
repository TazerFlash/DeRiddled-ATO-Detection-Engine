"""Calibrate the ATO model with temporal cross-fitting and choose ALLOW / CHALLENGE / BLOCK thresholds from the cost model."""
import json
import sys

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss

from deriddled.config import load_config, path
from deriddled.train import load, matrix

MODEL = load_config()["models"]["ato"]
BINS = [0, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1.0]


def margins(split: str = "valid", extra: tuple = ()) -> pd.DataFrame:
    models = path(load_config()["data"]["models_dir"])
    meta = json.loads((models / f"{MODEL}_meta.json").read_text())
    model = xgb.XGBClassifier()
    model.load_model(models / f"{MODEL}.json")
    df = load("ato", split)
    df["margin"] = model.predict(matrix(df, meta["features"], meta["categories"]), output_margin=True)
    df["raw_p"] = 1 / (1 + np.exp(-df["margin"]))
    return df[["login_id", "ts", "user_id", "country", "is_ato", "user_prior_logins", "margin", "raw_p", *extra]]


def fit_calibrator(method: str, margin: np.ndarray, y: np.ndarray):
    if method == "sigmoid":
        lr = LogisticRegression(C=1e6).fit(margin.reshape(-1, 1), y)
        return lambda m: lr.predict_proba(np.asarray(m).reshape(-1, 1))[:, 1]
    if method == "isotonic":
        iso = IsotonicRegression(out_of_bounds="clip", y_min=1e-7, y_max=1 - 1e-7).fit(margin, y)
        return lambda m: iso.predict(np.asarray(m))
    return lambda m: 1 / (1 + np.exp(-np.asarray(m)))


def cross_fit(df: pd.DataFrame, method: str) -> np.ndarray:
    folds = (df["ts"].dt.month == df["ts"].dt.month.min()).to_numpy()
    p = np.empty(len(df))
    for hold in (folds, ~folds):
        cal = fit_calibrator(method, df.loc[~hold, "margin"].to_numpy(), df.loc[~hold, "is_ato"].to_numpy().astype(int))
        p[hold] = cal(df.loc[hold, "margin"].to_numpy())
    return np.clip(p, 1e-9, 1 - 1e-9)


def reliability(p: np.ndarray, y: np.ndarray) -> pd.DataFrame:
    b = pd.cut(p, BINS, include_lowest=True)
    return (pd.DataFrame({"bin": b, "p": p, "y": y}).groupby("bin", observed=True)
            .agg(logins=("y", "size"), expected_ato=("p", "sum"), observed_ato=("y", "sum")))


def thresholds(costs: dict) -> tuple[float, float]:
    c_miss, c_otp, c_block, s = costs["c_miss"], costs["c_otp"], costs["c_block"], costs["otp_stop_rate"]
    challenge = c_otp / (s * c_miss + c_otp)
    block = (c_block - c_otp) / ((1 - s) * c_miss + c_block - c_otp)
    return challenge, max(block, challenge)


def decide(p: np.ndarray, t_challenge: float, t_block: float) -> np.ndarray:
    return np.where(p >= t_block, "BLOCK", np.where(p >= t_challenge, "CHALLENGE", "ALLOW"))


def realised_cost(actions: np.ndarray, y: np.ndarray, costs: dict) -> dict:
    c_miss, c_otp, c_block, s = costs["c_miss"], costs["c_otp"], costs["c_block"], costs["otp_stop_rate"]
    allow, chal, block = actions == "ALLOW", actions == "CHALLENGE", actions == "BLOCK"
    cost = (c_miss * (allow & y).sum() + (1 - s) * c_miss * (chal & y).sum()
            + c_otp * (chal & ~y).sum() + c_block * (block & ~y).sum())
    n = len(y)
    return {
        "challenge_rate": chal.mean(), "block_rate": block.mean(),
        "legit_block_rate": (block & ~y).sum() / (~y).sum(),
        "ato_challenged": int((chal & y).sum()), "ato_blocked": int((block & y).sum()), "ato_allowed": int((allow & y).sum()),
        "cost_per_1000": 1000 * cost / n,
    }


def sensitivity(p: np.ndarray, y: np.ndarray, base: dict) -> pd.DataFrame:
    rows = []
    scenarios = [("base", {})]
    for key, factors in (("c_miss", (0.5, 2)), ("c_otp", (0.5, 2)), ("c_block", (0.5, 2))):
        scenarios += [(f"{key} x{f}", {key: base[key] * f}) for f in factors]
    scenarios += [(f"otp_stop_rate {v}", {"otp_stop_rate": v}) for v in (0.8, 0.95)]
    for name, change in scenarios:
        costs = base | change
        tc, tb = thresholds(costs)
        rows.append({"scenario": name, "t_challenge": tc, "t_block": tb,
                     **realised_cost(decide(p, tc, tb), y, costs),
                     "cost_allow_all": 1000 * costs["c_miss"] * y.sum() / len(y)})
    return pd.DataFrame(rows)


def run() -> None:
    cfg = load_config()
    costs = cfg["costs"]
    df = margins("valid")
    y = df["is_ato"].to_numpy().astype(bool)
    pd.set_option("display.width", 250)

    print(f"validation: {len(df):,} logins, {y.sum()} ATO; Aug {int(y[df.ts.dt.month == 8].sum())}, Sep {int(y[df.ts.dt.month == 9].sum())}\n")
    cross = {}
    for method in ("raw", "sigmoid", "isotonic"):
        p = df["raw_p"].to_numpy() if method == "raw" else cross_fit(df, method)
        cross[method] = p
        print(f"== {method}: log loss {log_loss(y, p, labels=[0, 1]):.6f}  Brier {brier_score_loss(y, p):.3e}  "
              f"sum(p) {p.sum():.1f} vs {y.sum()} ATO")
        print(reliability(p, y).to_string(), "\n")

    best = min(("sigmoid", "isotonic"), key=lambda m: log_loss(y, cross[m], labels=[0, 1]))
    tc, tb = thresholds(costs)
    print(f"chosen calibrator: {best}; thresholds from costs: CHALLENGE p >= {tc:.5f}, BLOCK p >= {tb:.4f}\n")
    print("decision on validation (cross-fitted probabilities):")
    print(pd.Series(realised_cost(decide(cross[best], tc, tb), y, costs)).to_string(), "\n")
    print("sensitivity:")
    print(sensitivity(cross[best], y, costs).round(6).to_string(index=False), "\n")

    new = (df["user_prior_logins"] < cfg["serving"]["new_user_min_logins"]).to_numpy()
    acts = decide(cross[best], tc, tb)
    for name, mask in (("new users (<3 prior)", new), ("returning users", ~new)):
        print(f"{name}: {mask.mean():.1%} of logins, ATO {int(y[mask].sum())}, "
              f"challenge rate {(acts[mask] != 'ALLOW').mean():.3%}, ATO stopped {int(((acts != 'ALLOW') & y & mask).sum())}")

    final = fit_calibrator(best, df["margin"].to_numpy(), y.astype(int))
    grid = np.linspace(df["margin"].min(), df["margin"].max(), 2001)
    out = path(cfg["data"]["models_dir"]) / f"{MODEL}_calibration.json"
    out.write_text(json.dumps({"method": best, "margin_grid": grid.tolist(), "p_grid": final(grid).tolist(),
                               "t_challenge": tc, "t_block": tb, "costs": costs}, indent=1))
    print(f"\ncalibration + thresholds saved to {out}")


if __name__ == "__main__":
    run()
