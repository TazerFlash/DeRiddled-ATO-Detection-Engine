"""Ask the Watchtower: an LLM analyst agent that answers questions with read-only, time-limited SQL over the hashed analyst database."""
import argparse
import re
import threading
import time

import duckdb
import pandas as pd

from deriddled.analyst_db import DB
from deriddled.narrator import _client, _cost, _with_retries

MODEL = "claude-haiku-5-5"
PROMPT_VERSION = 3
ROW_LIMIT = 200
ROWS_SHOWN = 50
QUERY_TIMEOUT_S = 30
MAX_STEPS = 8
HISTORY_MAX = 50
USER_HASH = re.compile(r"^U-[0-9a-f]{10}$")

SYSTEM = """You are a fraud analyst assistant for an account-takeover detection team. You answer questions by querying a DuckDB database with the run_sql tool.

Database (DuckDB SQL dialect, read-only):

logins - every login attempt from 2020-02-03 up to 2020-09-14 inclusive, one row per attempt
  login_id BIGINT, ts TIMESTAMP, day DATE,
  user_hash VARCHAR (hashed account ID, 'U-' + 10 hex), ip_hash VARCHAR ('IP-...'), subnet_hash VARCHAR (hashed /24 IP range, 'NET-...'),
  country VARCHAR (ISO-2 code, e.g. 'NO', 'US'), region VARCHAR, city VARCHAR, asn BIGINT (network number),
  browser VARCHAR (name and version, e.g. 'Chrome 79.0.3945.130'), os VARCHAR (name and version), device_type VARCHAR ('desktop', 'mobile', 'tablet', 'bot', 'unknown'),
  rtt_ms DOUBLE (round-trip time, often NULL), login_successful BOOLEAN,
  is_attack_ip BOOLEAN (IP is on a known attack list), is_ato BOOLEAN (confirmed account takeover), is_non_account BOOLEAN (traffic that is not a real account, such as scanners)

decisions - the model's decision for every login in the replayed week 2020-09-08 to 2020-09-14
  login_id BIGINT (joins to logins.login_id), event_ts TIMESTAMP, user_hash VARCHAR, country VARCHAR,
  score DOUBLE (calibrated takeover probability), action VARCHAR ('ALLOW', 'CHALLENGE', 'BLOCK'),
  reasons VARCHAR (JSON list of plain-English reasons, empty for most ALLOW rows), model_version VARCHAR,
  latency_ms DOUBLE, fail_open BOOLEAN

Context: today is 2020-09-15, so "yesterday" is 2020-09-14 and "last week" is 2020-09-08 to 2020-09-14. An "account" is a distinct user_hash. Identifiers are hashed; never try to recover raw IPs or user IDs.

How to work:
- Write one SELECT (or WITH ... SELECT) statement per run_sql call. Results are capped at 200 rows.
- Look at the data before assuming values (for example SELECT DISTINCT on a column) when a filter depends on exact spellings.
- Explore and check with run_sql as much as you need. When you are done, call final_answer once with the single query whose result table answers the question and a one or two sentence answer. Only that query's table is shown to the analyst.
- The final_answer query returns one row per item asked for, with the asked-for columns. When the question asks for the single top item ("which X has the most", "which X is most common", "in which hour"), it returns only that one row (ORDER BY ... LIMIT 1), not a ranking. Mention runners-up in the answer text only if useful.
- Follow the question's units exactly (a percentage 0-100 versus a fraction 0-1, rounding, ordering).
- The answer text reports only what the final query returns."""

TOOLS = [
    {"name": "run_sql",
     "description": "Run one read-only DuckDB SELECT statement against the logins and decisions tables. Returns up to 200 rows as text, or an error message to fix.",
     "input_schema": {"type": "object", "properties": {"sql": {"type": "string", "description": "A single SELECT or WITH query."}},
                      "required": ["sql"], "additionalProperties": False}},
    {"name": "user_history",
     "description": "Return one account's most recent logins (newest first): time, place, network, hashed IP, browser, OS, device, success and takeover flag.",
     "input_schema": {"type": "object",
                      "properties": {"user_hash": {"type": "string", "description": "Hashed account ID such as U-1a2b3c4d5e."},
                                     "limit": {"type": "integer", "minimum": 1, "maximum": HISTORY_MAX}},
                      "required": ["user_hash"], "additionalProperties": False}},
    {"name": "final_answer",
     "description": "Finish: submit the one SELECT query whose result table answers the question, plus a one or two sentence answer. The query is run and its table shown to the analyst. If it fails, you get the error and can try again.",
     "input_schema": {"type": "object",
                      "properties": {"sql": {"type": "string", "description": "The single SELECT or WITH query that produces the answer table."},
                                     "answer": {"type": "string", "description": "One or two sentences stating the answer."}},
                      "required": ["sql", "answer"], "additionalProperties": False}},
]


class QueryRejected(Exception):
    pass


def connect() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(DB), read_only=True, config={
        "enable_external_access": False, "memory_limit": "2GB", "threads": 4, "lock_configuration": True})
    return con


def check(con: duckdb.DuckDBPyConnection, sql: str) -> str:
    sql = sql.strip().rstrip(";").strip()
    try:
        statements = con.extract_statements(sql)
    except duckdb.Error as exc:
        raise QueryRejected(f"could not parse: {exc}") from exc
    if len(statements) != 1:
        raise QueryRejected("send exactly one statement")
    if statements[0].type != duckdb.StatementType.SELECT:
        raise QueryRejected(f"only SELECT queries are allowed, got {statements[0].type.name}")
    return sql


def query(con: duckdb.DuckDBPyConnection, sql: str, limit: int = ROW_LIMIT, timeout_s: float = QUERY_TIMEOUT_S) -> tuple[pd.DataFrame, bool]:
    sql = check(con, sql)
    timer = threading.Timer(timeout_s, con.interrupt)
    timer.start()
    try:
        df = con.execute(f"SELECT * FROM ({sql}) AS q LIMIT {limit + 1}").df()
    except duckdb.InterruptException as exc:
        raise QueryRejected(f"query stopped after {timeout_s:.0f}s; filter by day or aggregate first") from exc
    finally:
        timer.cancel()
    return df.head(limit), len(df) > limit


def history(con: duckdb.DuckDBPyConnection, user_hash: str, limit: int = 20) -> pd.DataFrame:
    if not USER_HASH.match(user_hash or ""):
        raise QueryRejected("user_hash must look like U- followed by 10 hex characters")
    return con.execute("""SELECT ts, country, city, asn, ip_hash, browser, os, device_type, login_successful, is_ato
                          FROM logins WHERE user_hash = ? ORDER BY ts DESC LIMIT ?""",
                       [user_hash, max(1, min(int(limit), HISTORY_MAX))]).df()


def render(df: pd.DataFrame, truncated: bool = False) -> str:
    if df.empty:
        return "(0 rows)"
    text = df.head(ROWS_SHOWN).to_csv(index=False)
    note = f"({len(df)} rows{', more rows exist beyond the 200-row cap' if truncated else ''}"
    note += f"; first {ROWS_SHOWN} shown)" if len(df) > ROWS_SHOWN else ")"
    return f"{text}{note}"


def _tool(con, name: str, args: dict, trace: list) -> tuple[str, bool]:
    t = time.perf_counter()
    step = {"tool": name, "input": args}
    try:
        if name in ("run_sql", "final_answer"):
            df, truncated = query(con, args.get("sql", ""))
            step.update(sql=args.get("sql", ""), rows=len(df), truncated=truncated, result=df)
            out, error = render(df, truncated), False
        elif name == "user_history":
            df = history(con, args.get("user_hash", ""), args.get("limit", 20))
            step.update(rows=len(df), result=df)
            out, error = render(df), False
        else:
            out, error = f"unknown tool {name}", True
    except (QueryRejected, duckdb.Error) as exc:
        out, error = f"error: {str(exc)[:600]}", True
    step.update(error=out if error else None, seconds=round(time.perf_counter() - t, 3))
    trace.append(step)
    return out, error


def ask(question: str, client=None, model: str = MODEL, effort: str = "medium", con=None, max_steps: int = MAX_STEPS) -> dict:
    client = client or _client("claude")
    con = con or connect()
    messages = [{"role": "user", "content": question}]
    trace, tokens_in, tokens_out, answer, status = [], 0, 0, None, "max_steps"
    t = time.perf_counter()
    for _ in range(max_steps):
        response = _with_retries(lambda: client.beta.messages.create(
            model=model, max_tokens=16000, system=SYSTEM, tools=TOOLS, messages=messages,
            output_config={"effort": effort}))
        tokens_in += response.usage.input_tokens
        tokens_out += response.usage.output_tokens
        messages.append({"role": "assistant", "content": response.content})
        calls = [b for b in response.content if b.type == "tool_use"]
        if response.stop_reason != "tool_use" or not calls:
            answer = "\n".join(b.text for b in response.content if b.type == "text")
            status = response.stop_reason
            break
        results = []
        for b in calls:
            out, error = _tool(con, b.name, b.input, trace)
            results.append({"type": "tool_result", "tool_use_id": b.id, "content": out, "is_error": error})
        if any(s["tool"] == "final_answer" and not s["error"] for s in trace):
            break
        messages.append({"role": "user", "content": results})
    final = next((s for s in reversed(trace) if s["tool"] == "final_answer" and not s["error"]), None)
    last = final or next((s for s in reversed(trace) if s["tool"] == "run_sql" and not s["error"]), None)
    if final:
        answer, status = final["input"].get("answer", ""), "final_answer"
    return {"question": question, "model": model, "effort": effort, "prompt_version": PROMPT_VERSION, "status": status,
            "answer": answer, "declared": final is not None,
            "final_sql": last["sql"] if last else None, "final_result": last["result"] if last else None,
            "steps": [{k: v for k, v in s.items() if k != "result"} for s in trace],
            "input_tokens": tokens_in, "output_tokens": tokens_out, "cost_usd": _cost(model, tokens_in, tokens_out),
            "seconds": round(time.perf_counter() - t, 2)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("question")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--effort", default="medium")
    a = ap.parse_args()
    r = ask(a.question, model=a.model, effort=a.effort)
    for s in r["steps"]:
        print(f"[{s['tool']}] {s.get('sql') or s['input']}\n  -> {s['error'] or str(s['rows']) + ' rows'}")
    print(f"\n{r['answer']}\n\n{r['status']} | {r['input_tokens']} in / {r['output_tokens']} out | ${r['cost_usd']:.4f} | {r['seconds']}s")
