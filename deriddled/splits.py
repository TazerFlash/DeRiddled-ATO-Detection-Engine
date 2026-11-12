"""Turn the per-target time windows in config.yaml into a SQL CASE that labels rows train/valid/test."""
from deriddled.config import load_config

SPLITS = ("train", "valid", "test")
LABEL_COLUMN = {"ato": "is_ato", "attack_ip": "is_attack_ip"}


def windows(target: str) -> dict[str, tuple[str, str]]:
    cfg = load_config()["splits"][target]
    out = {name: tuple(cfg[name]) for name in SPLITS}
    for a, b in zip(SPLITS, SPLITS[1:]):
        if out[a][1] != out[b][0]:
            raise ValueError(f"{target}: {a} ends {out[a][1]} but {b} starts {out[b][0]}")
    return out


def split_case(target: str, ts_col: str = "ts") -> str:
    whens = "\n".join(
        f"    WHEN {ts_col} >= TIMESTAMP '{start}' AND {ts_col} < TIMESTAMP '{end}' THEN '{name}'"
        for name, (start, end) in windows(target).items()
    )
    return f"CASE\n{whens}\n    ELSE NULL\nEND"
