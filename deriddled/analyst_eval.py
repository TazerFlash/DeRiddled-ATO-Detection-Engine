"""Execution-accuracy eval for the analyst agent: run 30 hand-written questions and compare each final result table with the gold query's."""
import argparse
import datetime as dt
import json
import math
import time

import numpy as np
import pandas as pd
import yaml

from deriddled.analyst import MODEL, PROMPT_VERSION, ask, connect, query
from deriddled.config import ROOT, path
from deriddled.evaluate import wilson
from deriddled.narrator import _client

SETS = {"dev": ROOT / "eval" / "analyst_questions.yaml", "holdout": ROOT / "eval" / "analyst_holdout.yaml"}
LOG = path("data/ops/analyst_eval.jsonl")


def questions(name: str = "dev") -> list[dict]:
    return yaml.safe_load(SETS[name].read_text(encoding="utf-8"))


def summary_path(name: str, version: int):
    return path(f"data/ops/analyst_eval_summary_{name}_v{version}.json")


def _norm(v):
    if v is None or (isinstance(v, float) and math.isnan(v)) or v is pd.NaT:
        return None
    if isinstance(v, (bool, np.bool_)):
        return str(bool(v)).lower()
    if isinstance(v, pd.Timestamp | dt.datetime):
        v = pd.Timestamp(v)
        return v.date().isoformat() if v == v.normalize() else v.isoformat()
    if isinstance(v, dt.date):
        return v.isoformat()
    if isinstance(v, int | float | np.integer | np.floating):
        return float(v)
    try:
        return float(str(v).strip())
    except ValueError:
        return str(v).strip()


def _eq(a, b, tol: float) -> bool:
    if isinstance(a, float) and isinstance(b, float):
        return abs(a - b) <= max(tol, 1e-9 * max(abs(a), abs(b)))
    return a == b


def _key(v):
    return (0, v, "") if isinstance(v, float) else (1, 0.0, "" if v is None else str(v))


def _col_match(g: list, p: list, tol: float) -> bool:
    return all(_eq(a, b, tol) for a, b in zip(sorted(g, key=_key), sorted(p, key=_key)))


def compare(gold: pd.DataFrame, pred: pd.DataFrame | None, tol: float = 1e-6) -> bool:
    if pred is None or len(gold) != len(pred) or pred.shape[1] < gold.shape[1]:
        return False
    g = {c: [_norm(v) for v in gold[c]] for c in gold.columns}
    p = {i: [_norm(v) for v in pred.iloc[:, i]] for i in range(pred.shape[1])}
    mapping, used = {}, set()
    for c, vals in g.items():
        hit = next((i for i in p if i not in used and _col_match(vals, p[i], tol)), None)
        if hit is None:
            return False
        mapping[c], used = hit, used | {hit}
    gold_rows = [tuple(g[c][r] for c in gold.columns) for r in range(len(gold))]
    pred_rows = [tuple(p[mapping[c]][r] for c in gold.columns) for r in range(len(pred))]
    free = list(range(len(pred_rows)))
    for row in gold_rows:
        hit = next((j for j in free if all(_eq(a, b, tol) for a, b in zip(row, pred_rows[j]))), None)
        if hit is None:
            return False
        free.remove(hit)
    return True


def run(model: str = MODEL, effort: str = "medium", only: list[str] | None = None, name: str = "dev") -> dict:
    con, client = connect(), _client("claude")
    LOG.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for q in questions(name):
        if only and q["id"] not in only:
            continue
        gold, _ = query(con, q["gold"])
        try:
            r = ask(q["question"], client=client, model=model, effort=effort, con=con)
        except Exception as exc:
            r = {"status": f"error: {type(exc).__name__}", "answer": str(exc)[:300], "final_sql": None,
                 "final_result": None, "steps": [], "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "seconds": None}
        ok = compare(gold, r["final_result"], q.get("tol", 1e-6))
        rec = {"id": q["id"], "set": name, "prompt_version": PROMPT_VERSION, "tier": q["tier"], "model": model, "effort": effort, "correct": ok,
               "status": r["status"], "final_sql": r["final_sql"], "answer": r["answer"],
               "declared": r.get("declared", False), "sql_calls": sum(s["tool"] == "run_sql" for s in r["steps"]),
               "tool_errors": sum(bool(s["error"]) for s in r["steps"]),
               "history_calls": sum(s["tool"] == "user_history" for s in r["steps"]),
               "input_tokens": r["input_tokens"], "output_tokens": r["output_tokens"],
               "cost_usd": r["cost_usd"], "seconds": r["seconds"], "logged_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
        rows.append(rec)
        with LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        print(f"{q['id']} {'PASS' if ok else 'FAIL'}  {rec['sql_calls']} queries, {rec['tool_errors']} errors  "
              f"${rec['cost_usd']:.4f}  {rec['seconds']}s", flush=True)
    return summarize(rows, summary_path(name, PROMPT_VERSION))


def summarize(rows: list[dict], out_path) -> dict:
    df = pd.DataFrame(rows)
    k, n = int(df["correct"].sum()), len(df)
    out = {"set": df["set"].iloc[0], "prompt_version": int(df["prompt_version"].iloc[0]),
           "model": df["model"].iloc[0], "effort": df["effort"].iloc[0], "questions": n, "correct": k,
           "execution_accuracy": k / n, "ci_wilson": wilson(k, n),
           "by_tier": {t: f"{int(g['correct'].sum())}/{len(g)}" for t, g in df.groupby("tier", sort=False)},
           "failed": df.loc[~df["correct"], "id"].tolist(),
           "declared_final_answer": int(df["declared"].sum()), "mean_sql_calls": round(df["sql_calls"].mean(), 2), "tool_errors": int(df["tool_errors"].sum()),
           "cost_usd": round(df["cost_usd"].sum(), 4), "cost_per_1000_questions": round(1000 * df["cost_usd"].mean(), 2),
           "median_seconds": float(df["seconds"].median())}
    out_path.write_text(json.dumps(out, indent=2, default=float), encoding="utf-8")
    for key, v in out.items():
        print(f"{key}: {v}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--set", default="dev", choices=list(SETS))
    a = ap.parse_args()
    run(a.model, a.effort, a.only, a.set)
