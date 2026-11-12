"""Shadow-mode comparison on one split: rule (control) vs De-Riddled policy (treatment) on the same logins, with exact McNemar tests, block-bootstrap CIs and a power calculation."""
import json
import sys

import numpy as np
import pandas as pd
from scipy.stats import binom, binomtest

from deriddled.config import load_config, path
from deriddled.decision import MODEL, cross_fit, decide, margins, thresholds
from deriddled.evaluate import top_rate_flags

ALPHA = 0.05
POWER = 0.8


def policies(df: pd.DataFrame, cfg: dict) -> dict[str, np.ndarray]:
    calib = json.loads((path(cfg["data"]["models_dir"]) / f"{MODEL}_calibration.json").read_text())
    tc, tb = thresholds(cfg["costs"])
    model = decide(cross_fit(df, calib["method"]), tc, tb)
    rule = np.where(df["user_fails_1h"].to_numpy() >= cfg["rule_baseline"]["k"], "CHALLENGE", "ALLOW")
    budget = (model != "ALLOW").mean()
    lr = np.where(top_rate_flags(df["lr_score"].reset_index(drop=True), budget).to_numpy(), "CHALLENGE", "ALLOW")
    return {"rule": rule, "lr_matched": lr, "model": model}


def login_cost(actions: np.ndarray, y: np.ndarray, costs: dict) -> np.ndarray:
    c_miss, c_otp, c_block, s = costs["c_miss"], costs["c_otp"], costs["c_block"], costs["otp_stop_rate"]
    allow, chal, block = actions == "ALLOW", actions == "CHALLENGE", actions == "BLOCK"
    return np.select([allow & y, chal & y, chal & ~y, block & ~y], [c_miss, (1 - s) * c_miss, c_otp, c_block], 0.0)


def mcnemar(treat: np.ndarray, control: np.ndarray) -> dict:
    only_t, only_c = int((treat & ~control).sum()), int((~treat & control).sum())
    n = only_t + only_c
    p = binomtest(min(only_t, only_c), n, 0.5).pvalue if n else 1.0
    return {"both": int((treat & control).sum()), "treatment_only": only_t, "control_only": only_c,
            "neither": int((~treat & ~control).sum()), "p_value": p}


def block_bootstrap(blocks: pd.Series, cols: dict[str, np.ndarray], n_boot: int = 10_000, seed: int = 0) -> pd.DataFrame:
    sums = pd.DataFrame(cols).groupby(blocks.to_numpy()).sum()
    idx = np.random.default_rng(seed).integers(0, len(sums), size=(n_boot, len(sums)))
    return pd.DataFrame(sums.to_numpy()[idx].sum(axis=1), columns=sums.columns)


def ci(x: np.ndarray) -> tuple[float, float]:
    return tuple(np.percentile(x, [2.5, 97.5]))


def reject_prob(nd_max: int, q: float, alpha: float = ALPHA) -> np.ndarray:
    out = np.zeros(nd_max + 1)
    for nd in range(1, nd_max + 1):
        b = np.arange(nd + 1)
        pv = np.minimum(1.0, 2 * binom.cdf(np.minimum(b, nd - b), nd, 0.5))
        out[nd] = binom.pmf(b[pv <= alpha], nd, q).sum()
    return out


def mcnemar_power(n: int, p10: float, p01: float, alpha: float = ALPHA, _cache: dict = {}) -> float:
    pd_ = p10 + p01
    key = (round(p10 / pd_, 6), alpha)
    if key not in _cache or len(_cache[key]) <= n:
        _cache[key] = reject_prob(max(n, 400), p10 / pd_, alpha)
    nd = np.arange(n + 1)
    return float((binom.pmf(nd, n, pd_) * _cache[key][: n + 1]).sum())


def n_for_power(p10: float, p01: float, target: float = POWER, n_max: int = 400) -> int | None:
    return next((n for n in range(2, n_max + 1) if mcnemar_power(n, p10, p01) >= target), None)


def run(split: str = "valid") -> dict:
    cfg = load_config()
    costs = cfg["costs"]
    df = margins(split, extra=("user_fails_1h", "lr_score")).reset_index(drop=True)
    y = df["is_ato"].to_numpy().astype(bool)
    acts = policies(df, cfg)
    stop = {k: a != "ALLOW" for k, a in acts.items()}
    cost = {k: login_cost(a, y, costs) for k, a in acts.items()}
    camp = (df["country"] == cfg["rule_baseline"]["ato_campaign_country"]).to_numpy()
    months = (df["ts"].max() - df["ts"].min()).days / 30.44
    pd.set_option("display.width", 250)

    print(f"{split}: {len(df):,} logins, {y.sum()} ATO ({(y & camp).sum()} campaign), "
          f"{df.loc[y, 'user_id'].nunique()} ATO users, {months:.2f} months\n")

    summary = pd.DataFrame({k: {
        "challenge_rate": (acts[k] == "CHALLENGE").mean(), "block_rate": (acts[k] == "BLOCK").mean(),
        "legit_friction": stop[k][~y].mean(),
        "ato_stopped": int((stop[k] & y).sum()), "campaign_stopped": int((stop[k] & y & camp).sum()),
        "other_stopped": int((stop[k] & y & ~camp).sum()),
        "cost_per_1000": 1000 * cost[k].mean(),
    } for k in acts}).T
    summary.loc["allow_all"] = [0, 0, 0, 0, 0, 0, 1000 * costs["c_miss"] * y.sum() / len(y)]
    print(summary.to_string(), "\n")

    tests = {}
    for control in ("rule", "lr_matched"):
        tests[control] = {"ato": mcnemar(stop["model"][y], stop[control][y]),
                          "legit": mcnemar(stop["model"][~y], stop[control][~y])}
        for pop, t in tests[control].items():
            print(f"McNemar model vs {control} on {pop}: {t}")
    print()

    cols = {"n": np.ones(len(df)), "ato": y.astype(float), "legit": (~y).astype(float)}
    for k in acts:
        cols[f"stop_{k}"] = (stop[k] & y).astype(float)
        cols[f"fric_{k}"] = (stop[k] & ~y).astype(float)
        cols[f"cost_{k}"] = cost[k]
    days = block_bootstrap(df["ts"].dt.floor("D"), cols)
    users = block_bootstrap(df.loc[y, "user_id"], {k: v[y] for k, v in cols.items()})

    diffs = {}
    for control in ("rule", "lr_matched"):
        d = {
            "recall_diff_point": float(((stop["model"] & y).sum() - (stop[control] & y).sum()) / y.sum()),
            "recall_diff_ci_day": ci((days[f"stop_model"] - days[f"stop_{control}"]) / days["ato"]),
            "recall_diff_ci_user": ci((users[f"stop_model"] - users[f"stop_{control}"]) / users["ato"]),
            "friction_diff_point": float(stop["model"][~y].mean() - stop[control][~y].mean()),
            "friction_diff_ci_day": ci((days[f"fric_model"] - days[f"fric_{control}"]) / days["legit"]),
            "cost_diff_point": float(1000 * (cost["model"].mean() - cost[control].mean())),
            "cost_diff_ci_day": ci(1000 * (days[f"cost_model"] - days[f"cost_{control}"]) / days["n"]),
        }
        diffs[control] = d
        print(f"model minus {control}:")
        for k, v in d.items():
            print(f"  {k}: {np.round(v, 6)}")
    print()

    ato_per_month = y.sum() / months
    test_ato = 22
    rows = []
    for control in ("rule", "lr_matched"):
        t = tests[control]["ato"]
        p10, p01 = t["treatment_only"] / y.sum(), max(t["control_only"], 0.5) / y.sum()
        n80 = n_for_power(p10, p01)
        rows.append({"comparison": f"model vs {control} (observed discordance)", "p10": p10, "p01": p01,
                     "power_at_22": mcnemar_power(test_ato, p10, p01), f"power_at_{int(y.sum())}": mcnemar_power(int(y.sum()), p10, p01),
                     "n_ato_for_80pct": n80, "months_of_shadow": n80 / ato_per_month if n80 else None})
    for p10, p01 in ((0.30, 0.05), (0.20, 0.05), (0.15, 0.05), (0.10, 0.05), (0.10, 0.02)):
        n80 = n_for_power(p10, p01)
        rows.append({"comparison": f"planning grid", "p10": p10, "p01": p01,
                     "power_at_22": mcnemar_power(test_ato, p10, p01), f"power_at_{int(y.sum())}": mcnemar_power(int(y.sum()), p10, p01),
                     "n_ato_for_80pct": n80, "months_of_shadow": n80 / ato_per_month if n80 else None})
    power = pd.DataFrame(rows)
    print(f"power (exact McNemar, alpha {ALPHA}, two-sided); ATO rate {ato_per_month:.1f}/month:")
    print(power.round(3).to_string(index=False))

    out = path(cfg["data"]["models_dir"]).parent / "ops" / f"shadow_{split}.json"
    result = {"split": split, "summary": summary.reset_index(names="policy").to_dict("records"),
              "tests": tests, "diffs": diffs, "power": power.to_dict("records")}
    out.write_text(json.dumps(result, indent=1, default=float))
    print(f"\nsaved {out}")
    return result


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "valid")
