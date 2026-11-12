"""Build the public demo: a hashed data bundle staged in demo_space/, published as a Hugging Face dataset that the Streamlit Cloud app downloads."""
import argparse
import json
import os
import shutil
import sqlite3

import duckdb
import pandas as pd
import yaml
from dotenv import load_dotenv

from deriddled import casework, privacy
from deriddled.config import ROOT, load_config, path

OUT = ROOT / "demo_space"
DATA = OUT / "data"
EXAMPLES = [
    "How many logins were challenged or blocked on each day of the decision log?",
    "Which countries had more than 5 account takeovers, and how many each?",
    "What share of logins from known attack IPs had the correct password?",
    "Which networks (ASNs) had more than 3 account takeovers, and how many each?",
    "How many distinct accounts did the busiest IP touch in a single day, and on which day?",
    "What is the median number of logins per account?",
    "How many alerts in the decision log were CHALLENGE and how many were BLOCK?",
    "What share of account takeovers happened on an account's first-ever login?",
    "Which browser and OS combination appears most often among account takeovers?",
    "How many logins came from Norway, and what share of all logins is that?",
]
DATASET_README = """---
license: cc-by-4.0
pretty_name: De-Riddled demo bundle
tags: [fraud-detection, account-takeover, risk-based-authentication]
---

Hashed data bundle for the De-Riddled live dashboard demo: one replayed week of login decisions from an account-takeover model, the 156 alerts with their features and account histories, pre-written AI case summaries, saved analyst-agent answers, and a hashed analyst database.

Every account ID, IP address and IP range is a salted SHA-256 hash; no raw identifiers are included.

Code and method: https://github.com/TazerFlash/DeRiddled-ATO-Detection-Engine

Derived from the Login Data Set for Risk-Based Authentication, Wiefling et al., licensed CC BY 4.0 (https://github.com/das-group/rba-dataset). The source data is synthesised from real logins and must not be used in production systems.
"""
REQUIREMENTS = ["anthropic", "duckdb", "huggingface_hub", "matplotlib", "numpy", "pandas", "plotly", "pyarrow", "pycountry", "pydantic",
                "python-dotenv", "pyyaml", "scikit-learn", "streamlit", "xgboost"]


def _uid(user_id) -> int:
    return int(privacy.user(int(user_id))[2:], 16)


def _hash_sql(column: str, prefix: str) -> str:
    return f"'{prefix}-' || substr(sha256($salt || '|{prefix}|' || CAST({column} AS VARCHAR)), 1, 10)"


def bundle() -> None:
    cfg = load_config()
    alerts = casework.alerts()
    users = sorted(alerts["user_id"].astype(int).unique())
    uid = {u: _uid(u) for u in users}
    salt = privacy._salt()

    ops = DATA / "ops"
    ops.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(path(cfg["ops"]["sqlite_path"]))
    dec = pd.read_sql("SELECT * FROM decisions", src)
    src.close()
    flagged = dec["action"] != "ALLOW"
    dec["user_id"] = pd.array([uid.get(int(u)) if f else None for u, f in zip(dec["user_id"], flagged)], dtype="Int64")
    if dec.loc[flagged, "user_id"].isna().any():
        raise RuntimeError("some alerts lost their account mapping")
    dec.loc[~flagged, "reasons"] = "[]"
    db = ops / "ops.db"
    db.unlink(missing_ok=True)
    from deriddled.ops import SCHEMA
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    dec.to_sql("decisions", con, if_exists="append", index=False)
    con.commit()
    con.execute("VACUUM")
    con.close()
    print(f"decision log: {len(dec):,} rows, {flagged.sum()} alerts, {db.stat().st_size / 1e6:.1f} MB")

    logins = DATA / "parquet" / "logins"
    shutil.rmtree(logins, ignore_errors=True)
    logins.mkdir(parents=True)
    raw = path(cfg["data"]["logins_dir"]).as_posix()
    d = duckdb.connect()
    d.register("ids", pd.DataFrame({"user_id": list(uid), "uid": list(uid.values())}))
    ip_hash = _hash_sql("l.ip", "IP")
    net_hash = _hash_sql(r"regexp_extract(l.ip, '^(\d+\.\d+\.\d+)\.', 1)", "NET")
    d.execute(f"""
        COPY (
            SELECT l.login_id, l.ts, i.uid AS user_id, l.rtt_ms, {ip_hash} AS ip, {net_hash} AS subnet,
                   l.country, l.region, l.city, l.asn, l.browser, l.os, l.device_type, l.login_successful,
                   l.is_attack_ip, l.is_ato, l.is_non_account, l.month
            FROM read_parquet('{raw}/**/*.parquet', hive_partitioning = true) l JOIN ids i USING (user_id)
        ) TO '{logins.as_posix()}' (FORMAT parquet, PARTITION_BY (month))
    """, {"salt": salt})
    n = d.execute(f"SELECT COUNT(*) FROM read_parquet('{logins.as_posix()}/**/*.parquet')").fetchone()[0]
    print(f"login history: {n:,} rows for {len(uid)} accounts")

    feats = casework.alert_features(alerts)
    feats["user_id"] = feats["user_id"].astype(int).map(uid)
    (DATA / "demo").mkdir(parents=True, exist_ok=True)
    feats.to_parquet(DATA / "demo" / "alert_features.parquet", index=False)
    print(f"alert features: {feats.shape}")

    models = DATA / "models"
    models.mkdir(parents=True, exist_ok=True)
    name = cfg["models"]["ato"]
    for suffix in (".json", "_meta.json", "_calibration.json"):
        shutil.copy(path(cfg["data"]["models_dir"]) / f"{name}{suffix}", models)

    src_ops = path(cfg["data"]["models_dir"]).parent / "ops"
    for f in ("shadow_valid.json", "psi_by_month.csv"):
        shutil.copy(src_ops / f, ops)
    casework.registry_versions().to_csv(ops / "registry_versions.csv", index=False)

    from deriddled import narrator
    keep = {int(i) for i in alerts["login_id"]}
    rows = []
    for line in narrator.dashboard_path().read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r["login_id"] in keep and r.get("prompt_version") == narrator.PROMPT_VERSION and r.get("ato_model") == alerts["model_version"].iloc[0]:
                rows.append(line)
    (ops / "narratives_dashboard.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"case summaries: {len(rows)} of {len(keep)} alerts")

    from deriddled.analyst_db import DB
    (DATA / "analyst").mkdir(parents=True, exist_ok=True)
    shutil.copy(DB, DATA / "analyst" / "analyst.duckdb")

    demo_cfg = dict(cfg)
    demo_cfg["demo"] = {"enabled": True, "live_questions_per_session": 3, "live_questions_per_day": 100,
                        "max_question_chars": 300}
    demo_cfg["duckdb"] = {**cfg["duckdb"], "memory_limit": "1GB", "threads": 2}
    (OUT / "config.yaml").write_text(yaml.safe_dump(demo_cfg, sort_keys=False), encoding="utf-8")


def examples() -> None:
    from deriddled import analyst
    out = DATA / "ops" / "example_answers.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    saved = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    con = analyst.connect()
    for q in EXAMPLES:
        if q in saved:
            continue
        r = analyst.ask(q, con=con)
        res = r.pop("final_result")
        r["final_result"] = None if res is None else json.loads(res.to_json(orient="split", date_format="iso"))
        saved[q] = r
        out.write_text(json.dumps(saved, indent=1), encoding="utf-8")
        print(f"{r['status']:<12} ${r['cost_usd']:.4f} {q}")
    print(f"{len(saved)} example answers, ${sum(v['cost_usd'] for v in saved.values()):.3f}")


def stage() -> None:
    (OUT / "README.md").write_text(DATASET_README, encoding="utf-8")
    from importlib.metadata import version
    req = "\n".join(f"{p}=={version(p)}" for p in REQUIREMENTS) + "\n"
    (ROOT / "demo" / "requirements.txt").write_text(req, encoding="utf-8")
    leaks = [f for f in OUT.rglob("*") if f.name in (".env", "mlflow.db") or f.suffix in (".py", ".csv") and "rba" in f.name]
    if leaks:
        raise RuntimeError(f"refusing to stage private files: {leaks}")
    size = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file())
    print(f"staged {OUT} ({size / 1e6:.0f} MB) and demo/requirements.txt")


def publish(dataset: str) -> None:
    from huggingface_hub import HfApi
    load_dotenv(ROOT / ".env")
    token = os.environ.get("HF_TOKEN")
    if not token:
        raise RuntimeError("HF_TOKEN is not set in .env")
    api = HfApi(token=token)
    api.create_repo(dataset, repo_type="dataset", exist_ok=True)
    api.upload_folder(folder_path=str(OUT), repo_id=dataset, repo_type="dataset",
                      allow_patterns=["README.md", "config.yaml", "data/**"],
                      ignore_patterns=["data/duckdb_tmp/**", "**/live_usage.json", "*-wal", "*-shm"],
                      commit_message="Publish De-Riddled demo bundle")
    print(f"published: https://huggingface.co/datasets/{dataset}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["bundle", "examples", "stage", "all", "publish"])
    ap.add_argument("--dataset", default="TazerFlash/de-riddled-demo-data", help="Hugging Face dataset id")
    a = ap.parse_args()
    if a.cmd in ("bundle", "all"):
        bundle()
    if a.cmd in ("examples", "all"):
        examples()
    if a.cmd in ("stage", "all"):
        stage()
    if a.cmd == "publish":
        publish(a.dataset)
