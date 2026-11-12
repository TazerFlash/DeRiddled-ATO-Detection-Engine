"""Compare ATO policies with and without country-level features: protection, cost, and friction for legitimate Romanian users."""
import numpy as np
import pandas as pd

from deriddled.ablation import fit_cols
from deriddled.config import load_config
from deriddled.decision import cross_fit, decide, realised_cost, thresholds
from deriddled.errors import CAMPAIGN_BROWSER, CAMPAIGN_OS, ato_context, raw_columns
from deriddled.evaluate import top_rate_flags
from deriddled.train import NEG_FRAC, feature_list, load, matrix

VARIANTS = {
    "A current": [],
    "B no country reputation": ["country_ato_prior", "country_ato_rate"],
    "C B + no country rarity": ["country_ato_prior", "country_ato_rate", "country_freq"],
}


def run() -> None:
    costs = load_config()["costs"]
    tc, tb = thresholds(costs)
    train = load("ato", "train", "full", NEG_FRAC)
    valid = load("ato", "valid")
    y = valid.is_ato.to_numpy().astype(bool)

    ro = valid[(valid.country.astype(str) == "RO") & ~valid.is_ato]
    raw = raw_columns(ro.login_id).set_index("login_id")
    ato_users, ato_ips = ato_context()
    ro = ro.join(raw, on="login_id")
    sign = (((ro.browser == CAMPAIGN_BROWSER) & (ro.os == CAMPAIGN_OS)) | ro.user_id.isin(ato_users) | ro.ip.isin(ato_ips))
    genuine_ro = ro.index[~sign]
    print(f"Romanian legitimate logins: {len(ro):,} ({int(sign.sum())} with campaign signs, {len(genuine_ro):,} without)\n", flush=True)

    rows = []
    for name, drop in VARIANTS.items():
        cols = [c for c in feature_list("ato", "reputation") if c not in drop]
        model, cats = fit_cols(train, "is_ato", cols)
        df = valid[["ts", "is_ato"]].copy()
        df["margin"] = model.predict(matrix(valid, cols, cats), output_margin=True)
        p = cross_fit(df, "sigmoid")
        acts = decide(p, tc, tb)
        m = realised_cost(acts, y, costs)
        flag = pd.Series(acts != "ALLOW", index=valid.index)
        legit_flag = flag[~valid.is_ato]
        rows.append({
            "variant": name, "features": len(cols),
            "recall@1%": (top_rate_flags(pd.Series(df.margin.to_numpy()), 0.01).to_numpy() & y).sum(),
            "ato_stopped": 33 - m["ato_allowed"], "ato_blocked": m["ato_blocked"],
            "challenge_rate": m["challenge_rate"], "legit_blocks": int(((acts == "BLOCK") & ~y).sum()),
            "cost_per_1000": m["cost_per_1000"],
            "ro_legit_flag_rate": flag.loc[ro.index].mean(),
            "ro_genuine_flag_rate": flag.loc[genuine_ro].mean(),
            "ro_genuine_x_avg": flag.loc[genuine_ro].mean() / legit_flag.mean(),
            "ro_genuine_blocks": int((pd.Series(acts, index=valid.index).loc[genuine_ro] == "BLOCK").sum()),
        })
        print(f"{name} done", flush=True)

    out = pd.DataFrame(rows)
    pd.set_option("display.width", 250)
    print(out.to_string(index=False, formatters={
        "challenge_rate": "{:.4%}".format, "cost_per_1000": "{:.3f}".format, "ro_legit_flag_rate": "{:.2%}".format,
        "ro_genuine_flag_rate": "{:.2%}".format, "ro_genuine_x_avg": "{:.0f}".format}))


if __name__ == "__main__":
    run()
