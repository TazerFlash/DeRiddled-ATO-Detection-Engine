"""Rebuild ATO reputation with different label delays and compare the full main-model policy on validation."""
import sys
import time

import pandas as pd

from deriddled.ablation import fit_cols
from deriddled.config import load_config
from deriddled.decision import cross_fit, decide, realised_cost, thresholds
from deriddled.evaluate import top_rate_flags
from deriddled.reputation import build, delay_dir
from deriddled.train import NEG_FRAC, feature_list, load, matrix, segments

DELAYS = (1, 7, 14, 30)


def run(delays=DELAYS) -> None:
    costs = load_config()["costs"]
    tc, tb = thresholds(costs)
    cols = feature_list("ato", "main")
    rows, t0 = [], time.time()
    for d in delays:
        rep = delay_dir(d)
        if not rep.exists():
            build("full", d)
        train = load("ato", "train", "full", NEG_FRAC, rep_dir=rep)
        valid = load("ato", "valid", rep_dir=rep)
        model, cats = fit_cols(train, "is_ato", cols)
        df = valid[["ts", "is_ato"]].copy()
        df["margin"] = model.predict(matrix(valid, cols, cats), output_margin=True)
        y = df.is_ato.to_numpy().astype(bool)
        m = realised_cost(decide(cross_fit(df, "sigmoid"), tc, tb), y, costs)
        row = {"delay_days": d, "ato_stopped": int(y.sum()) - m["ato_allowed"], "challenge_rate": m["challenge_rate"],
               "cost_per_1000": m["cost_per_1000"],
               "valid_rows_with_rep": float((valid.asn_ato_prior > 0).mean())}
        score = pd.Series(df.margin.to_numpy(), index=valid.index)
        for seg, part in segments(valid, "ato").items():
            flags = top_rate_flags(score.loc[part.index], 0.01)
            row[f"recall@1%_{seg}"] = f"{int((flags & part.is_ato).sum())}/{int(part.is_ato.sum())}"
        rows.append(row)
        print(f"delay {d}d done ({time.time() - t0:.0f}s): {row}", flush=True)
    out = pd.DataFrame(rows)
    pd.set_option("display.width", 250)
    print(out.to_string(index=False, formatters={"challenge_rate": "{:.4%}".format, "cost_per_1000": "{:.3f}".format,
                                                 "valid_rows_with_rep": "{:.2%}".format}))


if __name__ == "__main__":
    run(tuple(int(x) for x in sys.argv[1:]) or DELAYS)
