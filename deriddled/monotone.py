"""Compare the main ATO model with and without monotone-increasing constraints on takeover-history features: validation recall, cost policy, seed variance and monotonicity violations."""
import json

import numpy as np
import pandas as pd
import xgboost as xgb

from deriddled.config import load_config, path
from deriddled.decision import MODEL, cross_fit, decide, realised_cost, thresholds
from deriddled.evaluate import top_rate_flags
from deriddled.train import NEG_FRAC, TAKEOVER_HISTORY, fit, load, matrix, save

SEEDS = (0, 1, 2)
CANDIDATE = "ato_xgb_mono"
PROBE_LOGIN = 15686673


def policy_metrics(valid: pd.DataFrame, margin: np.ndarray) -> dict:
    costs = load_config()["costs"]
    df = valid[["ts", "is_ato"]].copy()
    df["margin"] = margin
    y = df["is_ato"].to_numpy().astype(bool)
    tc, tb = thresholds(costs)
    m = realised_cost(decide(cross_fit(df, "sigmoid"), tc, tb), y, costs)
    caught = int((top_rate_flags(pd.Series(margin), 0.01).to_numpy() & y).sum())
    return {"caught_at_1pct": caught, "stopped": int(y.sum() - m["ato_allowed"]), "challenge_rate": m["challenge_rate"],
            "block_rate": m["block_rate"], "cost_per_1000": m["cost_per_1000"]}


def violations(model, cols, cats, rows: pd.DataFrame, feature: str, grid: np.ndarray) -> dict:
    margins = []
    for v in grid:
        r = rows.copy()
        r[feature] = v
        margins.append(model.predict(matrix(r, cols, cats), output_margin=True))
    m = np.vstack(margins)
    drops = np.diff(m, axis=0) < -1e-6
    return {"rows_with_a_drop": float(drops.any(axis=0).mean()), "max_drop": float(-np.diff(m, axis=0).min())}


def run() -> None:
    cfg = load_config()
    train = load("ato", "train", "full", NEG_FRAC)
    valid = load("ato", "valid", "full")
    print(f"train {len(train):,} rows ({int(train.is_ato.sum())} ATO), valid {len(valid):,} ({int(valid.is_ato.sum())} ATO)", flush=True)

    models_dir = path(cfg["data"]["models_dir"])
    champion = xgb.XGBClassifier()
    champion.load_model(models_dir / f"{MODEL}.json")
    champ_meta = json.loads((models_dir / f"{MODEL}_meta.json").read_text())
    champ_margin = champion.predict(matrix(valid, champ_meta["features"], champ_meta["categories"]), output_margin=True)

    rng = np.random.default_rng(0)
    probe_rows = pd.concat([valid[valid.is_ato], valid.iloc[rng.choice(len(valid), 3000, replace=False)]])
    grids = {f: np.unique(np.quantile(train[f].astype(float), np.linspace(0, 1, 41))) for f in TAKEOVER_HISTORY}
    grids = {f: np.union1d(g, np.arange(0, 11)) if f.endswith("_prior") else g for f, g in grids.items()}

    rows, checks, fitted = [], [], {}
    for variant, mono in (("unconstrained", ()), ("monotone", TAKEOVER_HISTORY)):
        for seed in SEEDS:
            model, cols, cats = fit(train, "ato", "main", 3, 1.0, seed=seed, monotone=mono)
            margin = model.predict(matrix(valid, cols, cats), output_margin=True)
            rows.append({"variant": variant, "seed": seed, **policy_metrics(valid, margin)})
            print(rows[-1], flush=True)
            if seed == 0:
                fitted[variant] = (model, cols, cats)
                if variant == "unconstrained":
                    print(f"  seed-0 refit vs saved champion: max |margin diff| {np.abs(margin - champ_margin).max():.2e}")
                for f in TAKEOVER_HISTORY:
                    checks.append({"variant": variant, "feature": f, **violations(model, cols, cats, probe_rows, f, grids[f])})

    pd.set_option("display.width", 250)
    res = pd.DataFrame(rows)
    print("\nper seed:\n", res.to_string(index=False))
    print("\nmean over seeds:\n", res.drop(columns="seed").groupby("variant").agg(["mean", "min", "max"]).round(5).T.to_string())
    chk = pd.DataFrame(checks)
    print("\nmonotonicity check (validation ATOs + 3,000 random logins, each feature swept over its training quantiles):\n",
          chk.round(4).to_string(index=False))

    probe = valid[valid.login_id == PROBE_LOGIN]
    if len(probe):
        print(f"\nprobe login {PROBE_LOGIN}: margin as asn_ato_prior goes 0..9")
        for variant, (model, cols, cats) in fitted.items():
            vals = []
            for k in range(10):
                r = probe.copy()
                r["asn_ato_prior"] = k
                vals.append(float(model.predict(matrix(r, cols, cats), output_margin=True)[0]))
            print(f"  {variant:13s} " + " ".join(f"{v:6.2f}" for v in vals))

    model, cols, cats = fitted["monotone"]
    save(model, CANDIDATE, cols, cats, "main", 3, 1.0, TAKEOVER_HISTORY)
    out = path(cfg["data"]["models_dir"]).parent / "ops" / "monotone_comparison.json"
    out.write_text(json.dumps({"per_seed": rows, "checks": checks}, indent=1, default=float))
    print(f"\ncandidate saved as {CANDIDATE}; results in {out}")


if __name__ == "__main__":
    run()
