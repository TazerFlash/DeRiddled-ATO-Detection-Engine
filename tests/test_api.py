"""Replay an hour of validation traffic through POST /score; check decisions match offline, reasons, fail-open and the SQLite log."""
import time

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from deriddled import api
from deriddled.config import connect, load_config, path
from deriddled.ops import OpsStore
from deriddled.parity import offline, replay_events

START, HOURS = pd.Timestamp("2020-09-15 11:00:00"), 1.0
cfg = load_config()["data"]
pytestmark = pytest.mark.skipif(not path(cfg["features_dir"]).exists(), reason="full feature tables not built")


@pytest.fixture(scope="module")
def replayed(tmp_path_factory):
    api.scorer = api.Scorer(ops=OpsStore(tmp_path_factory.mktemp("ops") / "ops.db"))
    client = TestClient(api.app)
    assert client.post("/warm_start", json={"start": str(START), "hours": HOURS}).status_code == 200
    events = replay_events(connect(), START, HOURS)
    responses = []
    for e in events.to_dict("records"):
        payload = {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in e.items()}
        payload["ts"] = pd.Timestamp(payload["ts"]).isoformat()
        r = client.post("/score", json=payload)
        assert r.status_code == 200, r.text
        responses.append(r.json())
    return client, events, pd.DataFrame(responses)


def test_no_fail_open_and_valid_actions(replayed):
    _, events, res = replayed
    assert len(res) == len(events)
    assert not res.fail_open.any()
    assert set(res.action) <= {"ALLOW", "CHALLENGE", "BLOCK"}


def test_flagged_logins_have_reasons(replayed):
    _, _, res = replayed
    flagged = res[res.action != "ALLOW"]
    assert flagged.top_reasons.map(len).between(1, 3).all()


def test_decisions_match_offline_policy(replayed):
    _, events, res = replayed
    s = api.scorer
    real = events.loc[~events.is_non_account, "login_id"]
    off = offline(connect(), real)
    p = np.interp(s.booster.predict(s._matrix_frame(off), output_margin=True), s.grid_m, s.grid_p)
    off_action = np.where(p >= s.t_block, "BLOCK", np.where(p >= s.t_challenge, "CHALLENGE", "ALLOW"))
    merged = res.merge(pd.DataFrame({"login_id": off.login_id, "offline_action": off_action, "offline_p": p}), on="login_id")
    assert len(merged) == len(real)
    assert (merged.action == merged.offline_action).all(), merged[merged.action != merged.offline_action].head().to_string()
    assert np.allclose(merged.score, merged.offline_p, rtol=1e-6, atol=1e-12)


def test_decisions_logged(replayed):
    _, events, _ = replayed
    counts = api.scorer.ops.counts()
    assert sum(c["n"] for c in counts.values()) == len(events)


def test_fail_open_on_timeout(replayed, monkeypatch):
    client, events, _ = replayed
    original = api.scorer.score

    def slow(event):
        time.sleep(0.3)
        return original(event)

    monkeypatch.setattr(api.scorer, "score", slow)
    e = events.iloc[-1].to_dict()
    payload = {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in e.items()}
    payload["ts"] = pd.Timestamp(payload["ts"]).isoformat()
    payload["login_id"] = -1
    r = client.post("/score", json=payload).json()
    assert r["fail_open"] and r["action"] == "ALLOW" and r["score"] is None
