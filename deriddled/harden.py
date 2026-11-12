"""Fix the red-team blind spot: train the success-only-novelty candidate, compare it with the champion on real validation, calibrate it, and save it."""
import json

import numpy as np
import pandas as pd
import xgboost as xgb

from deriddled.config import load_config, path
from deriddled.decision import fit_calibrator, thresholds
from deriddled.monotone import SEEDS, policy_metrics
from deriddled.train import NEG_FRAC, TAKEOVER_HISTORY, fit, load, matrix, save

CANDIDATE = "ato_xgb_ok"


def run() -> None:
    cfg = load_config()
    models = path(cfg["data"]["models_dir"])
    train = load("ato", "train", "full", NEG_FRAC)
    valid = load("ato", "valid", "full")
    y = valid["is_ato"].to_numpy().astype(bool)
    print(f"train {len(train):,} rows ({int(train.is_ato.sum())} ATO), valid {len(valid):,} ({int(y.sum())} ATO)", flush=True)

    flips = {f: int((valid[f].astype(bool) != valid[f"{f}_ok"].astype(bool)).sum()) for f in
             ("new_country", "new_asn", "new_device", "new_ip", "new_subnet24")}
    print("validation logins where success-only novelty differs from all-attempt novelty:", flips)
    print("validation ATOs where they differ:",
          {f: int((valid.loc[y, f].astype(bool) != valid.loc[y, f"{f}_ok"].astype(bool)).sum()) for f in flips})

    rows, fitted = [], {}
    for feature_set in ("main", "main_ok"):
        for seed in SEEDS:
            model, cols, cats = fit(train, "ato", feature_set, 3, 1.0, seed=seed, monotone=TAKEOVER_HISTORY)
            margin = model.predict(matrix(valid, cols, cats), output_margin=True)
            rows.append({"feature_set": feature_set, "seed": seed, **policy_metrics(valid, margin)})
            print(rows[-1], flush=True)
            if seed == 0:
                fitted[feature_set] = (model, cols, cats, margin)

    res = pd.DataFrame(rows)
    pd.set_option("display.width", 250)
    print("\nmean over seeds:\n", res.drop(columns="seed").groupby("feature_set").agg(["mean", "min", "max"]).round(5).T.to_string())

    model, cols, cats, margin = fitted["main_ok"]
    save(model, CANDIDATE, cols, cats, "main_ok", 3, 1.0, TAKEOVER_HISTORY)
    cal = fit_calibrator("sigmoid", margin, y.astype(int))
    grid = np.linspace(margin.min(), margin.max(), 2001)
    tc, tb = thresholds(cfg["costs"])
    (models / f"{CANDIDATE}_calibration.json").write_text(json.dumps(
        {"method": "sigmoid", "margin_grid": grid.tolist(), "p_grid": cal(grid).tolist(),
         "t_challenge": tc, "t_block": tb, "costs": cfg["costs"]}, indent=1))
    out = path("data/ops/harden_comparison.json")
    out.write_text(json.dumps({"per_seed": rows, "novelty_flips_valid": flips}, indent=1, default=float))
    print(f"\ncandidate saved as {CANDIDATE} with calibration; results in {out}")


if __name__ == "__main__":
    run()
