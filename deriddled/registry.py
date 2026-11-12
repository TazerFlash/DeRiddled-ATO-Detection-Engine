"""Log ATO and attack-IP models to MLflow with parameters and validation metrics, register them, and alias the champions."""
import json
import os
import sys

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")

import mlflow
import numpy as np
import pandas as pd
import xgboost as xgb
from mlflow import MlflowClient

from deriddled.config import load_config, path
from deriddled.decision import cross_fit, decide, realised_cost, thresholds
from deriddled.evaluate import top_rate_flags
from deriddled.train import NEG_FRAC, load, matrix

EXPERIMENT = "deriddled"
ATO_CANDIDATES = [("ato_xgb_reputation", "A: behaviour + network/IP/country reputation"),
                  ("ato_xgb_main", "C: no country features"),
                  ("ato_xgb_mono", "D: C + monotone-increasing takeover-history features"),
                  ("ato_xgb_ok", "E: D with novelty and likelihood measured against successful logins only (red-team fix, adopted)")]


def setup() -> MlflowClient:
    cfg = load_config()
    db = path(cfg["mlflow"]["tracking_uri"].replace("sqlite:///", ""))
    db.parent.mkdir(parents=True, exist_ok=True)
    mlflow.set_tracking_uri(f"sqlite:///{db.as_posix()}")
    artifacts = path(cfg["mlflow"]["artifact_root"])
    artifacts.mkdir(parents=True, exist_ok=True)
    if mlflow.get_experiment_by_name(EXPERIMENT) is None:
        mlflow.create_experiment(EXPERIMENT, artifact_location=artifacts.resolve().as_uri())
    mlflow.set_experiment(EXPERIMENT)
    return MlflowClient()


def _load_model(name: str):
    models = path(load_config()["data"]["models_dir"])
    model = xgb.XGBClassifier()
    model.load_model(models / f"{name}.json")
    meta = json.loads((models / f"{name}_meta.json").read_text())
    return model, meta, models


def ato_metrics(model, meta, valid: pd.DataFrame) -> dict:
    costs = load_config()["costs"]
    tc, tb = thresholds(costs)
    df = valid[["ts", "is_ato"]].copy()
    df["margin"] = model.predict(matrix(valid, meta["features"], meta["categories"]), output_margin=True)
    y = df.is_ato.to_numpy().astype(bool)
    m = realised_cost(decide(cross_fit(df, "sigmoid"), tc, tb), y, costs)
    caught = int((top_rate_flags(pd.Series(df.margin.to_numpy()), 0.01).to_numpy() & y).sum())
    return {"valid_recall_at_1pct": caught / y.sum(), "valid_ato_stopped": y.sum() - m["ato_allowed"],
            "valid_challenge_rate": m["challenge_rate"], "valid_legit_block_rate": m["legit_block_rate"],
            "valid_cost_per_1000": m["cost_per_1000"]}


def log_ato(client: MlflowClient, only: str | None = None) -> None:
    cfg = load_config()
    valid = load("ato", "valid")
    versions = {}
    for name, description in ATO_CANDIDATES:
        if only and name != only:
            continue
        model, meta, models = _load_model(name)
        with mlflow.start_run(run_name=name, description=description):
            mlflow.log_params({"target": "ato", "feature_set": meta["feature_set"], "max_depth": meta["depth"],
                               "scale_pos_weight": meta["spw"], "n_features": len(meta["features"]),
                               "neg_downsample": NEG_FRAC, "label_delay_days": cfg["reputation"]["label_delay_days"],
                               **{f"cost_{k}": v for k, v in cfg["costs"].items()}})
            mlflow.log_metrics(ato_metrics(model, meta, valid))
            mlflow.log_artifact(str(models / f"{name}_meta.json"))
            cal = models / f"{name}_calibration.json"
            if cal.exists():
                mlflow.log_artifact(str(cal))
            info = mlflow.xgboost.log_model(model, name="model", registered_model_name="deriddled-ato")
            versions[name] = info.registered_model_version
        print(f"logged {name} as deriddled-ato v{versions[name]}", flush=True)
    if cfg["models"]["ato"] in versions:
        champion = versions[cfg["models"]["ato"]]
        client.set_registered_model_alias("deriddled-ato", "champion", champion)
        print(f"deriddled-ato champion -> v{champion}")


def log_attack_ip(client: MlflowClient) -> None:
    name = load_config()["models"]["attack_ip"]
    model, meta, models = _load_model(name)
    valid = load("attack_ip", "valid")
    s = pd.Series(model.predict(matrix(valid, meta["features"], meta["categories"]), output_margin=True))
    y = valid.is_attack_ip.to_numpy()
    with mlflow.start_run(run_name=name, description="attack-IP behaviour model"):
        mlflow.log_params({"target": "attack_ip", "feature_set": meta["feature_set"], "max_depth": meta["depth"],
                           "scale_pos_weight": meta["spw"], "n_features": len(meta["features"])})
        for rate in (0.01, 0.05, 0.10, 0.20):
            f = top_rate_flags(s, rate).to_numpy()
            mlflow.log_metric(f"valid_recall_at_{int(rate * 100)}pct", float((f & y).sum() / y.sum()))
            mlflow.log_metric(f"valid_precision_at_{int(rate * 100)}pct", float((f & y).sum() / f.sum()))
        mlflow.log_artifact(str(models / f"{name}_meta.json"))
        info = mlflow.xgboost.log_model(model, name="model", registered_model_name="deriddled-attack-ip")
    client.set_registered_model_alias("deriddled-attack-ip", "champion", info.registered_model_version)
    print(f"logged {name} as deriddled-attack-ip v{info.registered_model_version} (champion)")


def summary(client: MlflowClient) -> None:
    for rm in client.search_registered_models():
        print(f"\n{rm.name}  aliases={rm.aliases}")
        for v in sorted(client.search_model_versions(f"name='{rm.name}'"), key=lambda v: int(v.version)):
            run = client.get_run(v.run_id)
            metrics = {k: round(val, 5) for k, val in run.data.metrics.items()}
            print(f"  v{v.version}  run={run.info.run_name}  {metrics}")


if __name__ == "__main__":
    c = setup()
    if len(sys.argv) > 2 and sys.argv[1] == "add":
        log_ato(c, only=sys.argv[2])
    else:
        log_ato(c)
        log_attack_ip(c)
    summary(c)
