"""FastAPI scoring service: POST /score returns a calibrated ATO score, ALLOW / CHALLENGE / BLOCK and top-3 reasons, failing open on timeout."""
import asyncio
import gc
import hashlib
import json
import threading
import time
from datetime import datetime
from types import SimpleNamespace

import numpy as np
import pandas as pd
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from deriddled.config import connect, load_config, path
from deriddled.explain import GROUPS, TEMPLATES
from deriddled.ops import OpsStore
from deriddled.parity import replay_events, warm_start
from deriddled.state import OnlineState


class LoginEvent(BaseModel):
    login_id: int
    ts: datetime
    user_id: int
    ip: str
    asn: int
    country: str
    browser: str | None = None
    os: str | None = None
    device_type: str | None = None
    rtt_ms: float | None = None
    login_successful: bool
    is_attack_ip: bool = Field(False, description="threat-intel flag for this IP; updates state only")
    is_ato: bool = Field(False, description="confirmed takeover; enters reputation only after the label delay")
    is_non_account: bool = False


class ScoreResponse(BaseModel):
    login_id: int
    score: float | None
    action: str
    top_reasons: list[str]
    model_version: str
    latency_ms: float
    fail_open: bool


class LabelRequest(BaseModel):
    login_id: int
    label: str
    analyst: str | None = None


class WarmStartRequest(BaseModel):
    start: datetime
    hours: float = 3.0


class GcMonitor:
    """Records garbage-collector pauses so /health can report the worst one."""

    def __init__(self):
        self.started = {}
        self.max_ms = {0: 0.0, 1: 0.0, 2: 0.0}
        self.count = {0: 0, 1: 0, 2: 0}
        gc.callbacks.append(self)

    def __call__(self, phase: str, info: dict) -> None:
        g = info["generation"]
        if phase == "start":
            self.started[g] = time.perf_counter()
        elif g in self.started:
            self.max_ms[g] = max(self.max_ms[g], (time.perf_counter() - self.started.pop(g)) * 1000)
            self.count[g] += 1


GC = GcMonitor()


class Scorer:
    def __init__(self, ops: OpsStore | None = None):
        cfg = load_config()
        models = path(cfg["data"]["models_dir"])
        name = cfg["models"]["ato"]
        raw = (models / f"{name}.json").read_bytes()
        self.version = f"{name}:{hashlib.sha256(raw).hexdigest()[:8]}"
        self.booster = xgb.Booster()
        self.booster.load_model(bytearray(raw))
        self.booster.set_param({"nthread": 1})
        self.meta = json.loads((models / f"{name}_meta.json").read_text())
        cal = json.loads((models / f"{name}_calibration.json").read_text())
        self.grid_m, self.grid_p = np.array(cal["margin_grid"]), np.array(cal["p_grid"])
        self.t_challenge, self.t_block = cal["t_challenge"], cal["t_block"]
        self.timeout = cfg["serving"]["timeout_ms"] / 1000
        self.state = OnlineState()
        self.lock = threading.Lock()
        self.ops = ops or OpsStore()
        cats = self.meta["categories"]["device_type"]
        self.device_dtype = pd.CategoricalDtype(cats)
        self.device_code = {c: float(i) for i, c in enumerate(cats)}

    def warm_start(self, start: pd.Timestamp, hours: float) -> int:
        con = connect()
        ev = replay_events(con, start, hours)
        with self.lock:
            self.state = warm_start(con, start, ev)
            gc.collect()
            gc.freeze()
            gc.set_threshold(10_000, 50, 1_000)
        return len(ev)

    def _matrix_frame(self, df: pd.DataFrame) -> xgb.DMatrix:
        X = df[self.meta["features"]].copy()
        for c in X.columns:
            if X[c].dtype == bool:
                X[c] = X[c].astype(int)
        X["device_type"] = pd.Categorical(X["device_type"].astype(object).where(X["device_type"].notna()),
                                          dtype=self.device_dtype)
        return xgb.DMatrix(X, enable_categorical=True)

    def _matrix(self, f: dict) -> xgb.DMatrix:
        return self._matrix_frame(pd.DataFrame([{k: f[k] for k in self.meta["features"]}]))

    def _vector(self, f: dict) -> np.ndarray:
        return np.array([[self.device_code.get(f[k], np.nan) if k == "device_type" else float(f[k])
                          for k in self.meta["features"]]], dtype=np.float32)

    def _reasons(self, x: np.ndarray, row: SimpleNamespace) -> list[str]:
        dm = xgb.DMatrix(x, feature_names=self.meta["features"], feature_types=self.booster.feature_types,
                         enable_categorical=True)
        contrib = self.booster.predict(dm, pred_contribs=True)[0, :-1]
        by_feature = dict(zip(self.meta["features"], contrib))
        groups = {g: sum(by_feature.get(c, 0.0) for c in cols) for g, cols in GROUPS.items()}
        top = sorted((v, g) for g, v in groups.items() if v > 0)[::-1][:3]
        return [TEMPLATES[g](row) for _, g in top]

    def score(self, event: LoginEvent) -> dict:
        with self.lock:
            e, f = self.state.score_stream(event.model_dump())
        if event.is_non_account:
            return {"score": None, "action": "ALLOW", "top_reasons": ["Unknown account: not scored for takeover"]}
        x = self._vector(f)
        margin = float(self.booster.inplace_predict(x, predict_type="margin")[0])
        p = float(np.interp(margin, self.grid_m, self.grid_p))
        action = "BLOCK" if p >= self.t_block else "CHALLENGE" if p >= self.t_challenge else "ALLOW"
        reasons = []
        if action != "ALLOW":
            reasons = self._reasons(x, SimpleNamespace(**f, country=e["country"], asn=e["asn"]))
        return {"score": p, "action": action, "top_reasons": reasons}


app = FastAPI(title="De-Riddled", version="0.1.0")
scorer: Scorer | None = None


def get_scorer() -> Scorer:
    global scorer
    if scorer is None:
        scorer = Scorer()
    return scorer


@app.get("/health")
def health() -> dict:
    s = get_scorer()
    return {"status": "ok", "model_version": s.version, "users_in_state": len(s.state.user),
            "decisions": s.ops.counts(), "gc_max_pause_ms": {g: round(v, 1) for g, v in GC.max_ms.items()},
            "gc_collections": GC.count, "gc_frozen_objects": gc.get_freeze_count()}


@app.post("/warm_start")
def warm(req: WarmStartRequest) -> dict:
    t0 = time.perf_counter()
    n = get_scorer().warm_start(pd.Timestamp(req.start), req.hours)
    return {"replay_events": n, "seconds": round(time.perf_counter() - t0, 1)}


@app.post("/score", response_model=ScoreResponse)
async def score(event: LoginEvent) -> ScoreResponse:
    s = get_scorer()
    t0 = time.perf_counter()
    fail_open, error = False, None
    try:
        result = await asyncio.wait_for(run_in_threadpool(s.score, event), timeout=s.timeout)
    except asyncio.TimeoutError:
        fail_open, error = True, f"timeout > {s.timeout * 1000:.0f} ms"
    except Exception as exc:
        fail_open, error = True, f"{type(exc).__name__}: {exc}"
    if fail_open:
        result = {"score": None, "action": "ALLOW", "top_reasons": []}
    resp = ScoreResponse(login_id=event.login_id, model_version=s.version, fail_open=fail_open,
                         latency_ms=round((time.perf_counter() - t0) * 1000, 3), **result)
    s.ops.log_decision({**resp.model_dump(), "event_ts": event.ts, "user_id": event.user_id,
                        "country": event.country, "error": error})
    return resp


@app.post("/label")
def label(req: LabelRequest) -> dict:
    if req.label not in ("confirmed_fraud", "false_alarm"):
        raise HTTPException(422, "label must be 'confirmed_fraud' or 'false_alarm'")
    get_scorer().ops.add_label(req.login_id, req.label, req.analyst)
    return {"ok": True}


@app.get("/alerts")
def alerts(limit: int = 100) -> list[dict]:
    return get_scorer().ops.recent_alerts(limit)
