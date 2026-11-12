"""Analyst agent: SQL guardrails, result comparison for execution accuracy, and the tool loop with a fake model client."""
from types import SimpleNamespace

import pandas as pd
import pytest

from deriddled.analyst import QueryRejected, ask, connect, history, query
from deriddled.analyst_db import DB
from deriddled.analyst_eval import compare

needs_db = pytest.mark.skipif(not DB.exists(), reason="analyst database not built")


@pytest.fixture(scope="module")
def con():
    return connect()


@needs_db
@pytest.mark.parametrize("sql", [
    "DELETE FROM logins",
    "CREATE TABLE x AS SELECT 1",
    "ATTACH 'data/ops/ops.db' AS o",
    "SELECT 1; DROP TABLE logins",
    "SET enable_external_access = true",
    "COPY logins TO 'leak.csv'",
    "SELECT * FROM read_parquet('data/parquet/logins/**/*.parquet')",
    "SELECT * FROM read_csv('data/raw/rba-dataset.csv')",
])
def test_rejects_unsafe_sql(con, sql):
    with pytest.raises(Exception):
        query(con, sql)


@needs_db
def test_row_cap_and_timeout(con):
    df, truncated = query(con, "SELECT login_id FROM logins", limit=50)
    assert len(df) == 50 and truncated
    with pytest.raises(QueryRejected, match="stopped"):
        query(con, "SELECT COUNT(*) FROM logins a JOIN logins b ON a.asn = b.asn", timeout_s=1)


@needs_db
def test_no_raw_identifiers(con):
    cols = set(con.execute("SELECT column_name FROM information_schema.columns").df()["column_name"])
    assert not {"user_id", "ip", "user_agent"} & cols
    assert con.execute("SELECT COUNT(*) FROM logins WHERE user_hash NOT SIMILAR TO 'U-[0-9a-f]{10}'").fetchone()[0] == 0


@needs_db
def test_history_rejects_bad_hash(con):
    with pytest.raises(QueryRejected):
        history(con, "x' OR 1=1 --")


def test_compare_ignores_names_order_and_extra_columns():
    gold = pd.DataFrame({"asn": [1, 2], "accounts": [10, 20]})
    pred = pd.DataFrame({"n": [20, 10], "network": ["2", "1"], "extra": ["a", "b"]})
    assert compare(gold, pred)


def test_compare_keeps_rows_together():
    gold = pd.DataFrame({"asn": [1, 2], "accounts": [10, 20]})
    assert not compare(gold, pd.DataFrame({"asn": [1, 2], "accounts": [20, 10]}))


def test_compare_tolerance_and_units():
    gold = pd.DataFrame({"pct": [45.5]})
    assert compare(gold, pd.DataFrame({"x": [45.503]}), tol=0.0051)
    assert not compare(gold, pd.DataFrame({"x": [0.455]}), tol=0.0051)
    assert not compare(gold, pd.DataFrame({"x": [45.6]}), tol=0.0051)


def test_compare_dates_and_row_counts():
    gold = pd.DataFrame({"day": pd.to_datetime(["2020-09-08"]), "n": [3]})
    assert compare(gold, pd.DataFrame({"day": ["2020-09-08"], "n": [3]}))
    assert not compare(gold, pd.DataFrame({"day": ["2020-09-08", "2020-09-09"], "n": [3, 3]}))
    assert not compare(gold, None)


class FakeClient:
    def __init__(self, replies):
        self.replies, self.seen = list(replies), []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.seen.append({**kw, "messages": list(kw["messages"])})
        return self.replies.pop(0)


def _reply(stop, *blocks):
    return SimpleNamespace(stop_reason=stop, content=list(blocks), usage=SimpleNamespace(input_tokens=100, output_tokens=20))


@needs_db
def test_agent_loop_feeds_errors_back_and_keeps_last_good_query(con):
    tool = lambda i, sql: SimpleNamespace(type="tool_use", id=i, name="run_sql", input={"sql": sql})
    client = FakeClient([
        _reply("tool_use", tool("t1", "SELECT COUNT(*) AS n FROM no_such_table")),
        _reply("tool_use", tool("t2", "SELECT COUNT(*) AS n FROM decisions WHERE action = 'BLOCK'")),
        _reply("end_turn", SimpleNamespace(type="text", text="3 logins were blocked.")),
    ])
    r = ask("How many logins were blocked?", client=client, con=con)
    first_result = client.seen[1]["messages"][-1]["content"][0]
    assert first_result["is_error"] and "no_such_table" in first_result["content"]
    assert r["status"] == "end_turn" and r["answer"] == "3 logins were blocked."
    assert r["final_result"].iloc[0, 0] == 3 and len(r["steps"]) == 2


@needs_db
def test_declared_final_answer_wins_over_later_checks(con):
    use = lambda i, name, **kw: SimpleNamespace(type="tool_use", id=i, name=name, input=kw)
    client = FakeClient([
        _reply("tool_use", use("t1", "run_sql", sql="SELECT action, COUNT(*) FROM decisions GROUP BY action")),
        _reply("tool_use", use("t2", "final_answer", sql="SELECT COUNT(*) AS n FROM decisions WHERE action = 'BLOCK'",
                               answer="3 logins were blocked.")),
    ])
    r = ask("How many logins were blocked?", client=client, con=con)
    assert r["declared"] and r["status"] == "final_answer" and r["answer"] == "3 logins were blocked."
    assert r["final_result"].shape == (1, 1) and r["final_result"].iloc[0, 0] == 3 and len(client.seen) == 2
