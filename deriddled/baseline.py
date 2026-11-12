"""Static rule baseline (challenge after k failed attempts by the user in the past hour), evaluated on a split."""
import sys

import pandas as pd

from deriddled.config import load_config
from deriddled.evaluate import flag_metrics, load_split
from deriddled.splits import LABEL_COLUMN


def rule_flags(df: pd.DataFrame, k: int) -> pd.Series:
    return df["user_fails_1h"] >= k


def evaluate_rule(target: str, split: str = "valid", ks=range(1, 11)) -> pd.DataFrame:
    cfg = load_config()["rule_baseline"]
    label = LABEL_COLUMN[target]
    df = load_split(target, split, ["user_fails_1h"])
    segments = {"all": df}
    if target == "ato":
        campaign = df["country"] == cfg["ato_campaign_country"]
        segments |= {"campaign": df[campaign | ~df[label]], "other": df[~campaign | ~df[label]]}

    rows = []
    for k in ks:
        for seg, part in segments.items():
            m = flag_metrics(part, rule_flags(part, k), label)
            rows.append({"target": target, "split": split, "k": k, "segment": seg, **m})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "valid"
    out = pd.concat([evaluate_rule(t, split) for t in ("ato", "attack_ip")])
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 20)
    print(out.to_string(index=False))
