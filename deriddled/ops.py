"""SQLite (WAL) operational store: decision log written in batches by a background thread, plus analyst labels."""
import atexit
import json
import queue
import sqlite3
import threading
from datetime import datetime, timezone

from deriddled.config import load_config, path

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    login_id      INTEGER PRIMARY KEY,
    event_ts      TEXT NOT NULL,
    user_id       INTEGER,
    country       TEXT,
    score         REAL,
    action        TEXT NOT NULL,
    reasons       TEXT,
    model_version TEXT,
    latency_ms    REAL,
    fail_open     INTEGER NOT NULL,
    error         TEXT,
    logged_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_action ON decisions(action, score);
CREATE TABLE IF NOT EXISTS labels (
    login_id   INTEGER PRIMARY KEY,
    label      TEXT NOT NULL CHECK (label IN ('confirmed_fraud', 'false_alarm')),
    analyst    TEXT,
    labelled_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class OpsStore:
    def __init__(self, db_path=None):
        p = path(load_config()["ops"]["sqlite_path"]) if db_path is None else db_path
        p.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(p, check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()
        self.queue: queue.Queue = queue.Queue()
        self.writer = threading.Thread(target=self._drain, name="decision-writer", daemon=True)
        self.writer.start()
        atexit.register(self.flush)

    @staticmethod
    def _row(d: dict) -> tuple:
        return (d["login_id"], str(d["event_ts"]), d.get("user_id"), d.get("country"), d.get("score"), d["action"],
                json.dumps(d.get("top_reasons", [])), d.get("model_version"), d.get("latency_ms"),
                int(d.get("fail_open", False)), d.get("error"), d.get("logged_at") or _now())

    def log_decision(self, d: dict) -> None:
        self.queue.put(self._row({**d, "logged_at": _now()}))

    def _drain(self) -> None:
        while True:
            batch = [self.queue.get()]
            while len(batch) < 1000:
                try:
                    batch.append(self.queue.get_nowait())
                except queue.Empty:
                    break
            with self.lock:
                self.conn.execute("BEGIN")
                self.conn.executemany("INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                self.conn.execute("COMMIT")
            for _ in batch:
                self.queue.task_done()

    def flush(self) -> None:
        self.queue.join()

    def add_label(self, login_id: int, label: str, analyst: str | None = None) -> None:
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO labels VALUES (?,?,?,?)", (login_id, label, analyst, _now()))

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        self.flush()
        cur = self.conn.execute(
            "SELECT * FROM decisions WHERE action != 'ALLOW' ORDER BY score DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def counts(self) -> dict:
        self.flush()
        rows = self.conn.execute("SELECT action, COUNT(*), SUM(fail_open) FROM decisions GROUP BY action").fetchall()
        return {a: {"n": n, "fail_open": int(f or 0)} for a, n, f in rows}
