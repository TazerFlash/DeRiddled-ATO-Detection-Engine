"""LLM case narrator: builds a hashed evidence packet per alert, asks Gemini or Claude for a cited JSON case summary, and strips claims the evidence does not support."""
import argparse
import hashlib
import json
import math
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Literal

import pandas as pd
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict

from deriddled import casework, privacy
from deriddled.config import ROOT, load_config, path

MODEL = "claude-opus-5-5"
PRICES = {"claude-opus-5-5": (4.0, 20.0), "claude-opus-5": (5.0, 25.0), "claude-opus-4-8": (5.0, 25.0),
          "claude-sonnet-5-5": (2.0, 10.0), "claude-haiku-5-5": (0.10, 0.50)}
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1", "claude-fable-5-2"}
HISTORY = 10
PROMPT_VERSION = 5
ACTIONS = ("confirm_takeover", "contact_user_out_of_band", "likely_false_alarm", "needs_more_information")

SYSTEM = """You write case summaries for fraud analysts reviewing login alerts from an account-takeover model.

The model has already decided the action (CHALLENGE or BLOCK); you do not change it. Your job is to explain the case so an analyst can review it in under a minute.

Rules:
- Use only the evidence items given. Every claim must cite the IDs of the evidence items that support it, e.g. ["L0", "F3"].
- Copy numbers exactly as they appear in the cited evidence. Do not compute new numbers, percentages or durations.
- Write 4 to 6 claims, each one sentence, most important first. Cover what is unusual about this login compared with the account's history, and any network or IP context.
- Do not restate the model decision or probability as a claim; the analyst already sees it. If you mention the probability, compare it with the thresholds given in A1, never call it low or high on its own.
- Do not state causes or links between evidence items (such as "because", "due to", "yielding", "which explains") unless an evidence item states that link. State facts side by side instead.
- Keep each fact attached to what it measures: for example, time since the previous successful login is not time since the previous login.
- Mention evidence that points towards a false alarm as well as evidence for a takeover.
- Identifiers are hashed (U-..., IP-..., NET-...). Refer to them as given; never guess real identities, locations beyond the evidence, or motives.
- A claim about the account's earlier logins in general ("all", "every", "always", "only", "consistently", a total count) must cite H1 and every login it generalises over. Otherwise describe only the logins you cite ("L1 and L4 came from Norway").
- Network shares in F items are site-wide: they describe all users' logins, not this account's. Say "of all users' earlier logins", never "of this account's logins".
- A likelihood-ratio score above 0 means more typical of attacks than of this account; below 0 means more typical of this account.
- Feature flags say whether the account has used this country, network, IP range, IP or device before: "yes (seen before)" means familiar, "no (first time)" means new. They say nothing about cities; never say a city is new or familiar.
- Do not call the person behind this login an attacker or the account holder; say "this login". The evidence shows signals, not who logged in.
- Do not rank or compare signals ("the main signal", "the strongest", "worse than", "a long gap") unless an evidence item states the ranking or comparison.
- recommended_action is a suggestion for the analyst. Cite the evidence behind it in action_evidence_ids. Choose by these rules:
  - If this login's password was wrong (L0: password correct: no), the attacker did not get in on this login, so never choose confirm_takeover. Choose likely_false_alarm when the login matches the account's history (country, network or device seen before) and the network has few attack IPs and no confirmed takeovers; choose contact_user_out_of_band when the network or IP looks like an attack source, because the password may be under attack.
  - If the password was correct, choose confirm_takeover when the network or IP has confirmed takeovers and mostly attack IPs and the login does not match the account's history; contact_user_out_of_band when the evidence is mixed; likely_false_alarm when the login matches the account's history and the network is clean.
  - Choose needs_more_information when the account has little or no history and the network evidence is weak either way.
- confidence is your confidence in the recommended action: high only when the evidence points one way, low when it is evenly split or thin, medium otherwise."""

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["claims", "recommended_action", "action_evidence_ids", "confidence"],
    "properties": {
        "claims": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["text", "evidence_ids"],
            "properties": {"text": {"type": "string"}, "evidence_ids": {"type": "array", "items": {"type": "string"}}}}},
        "recommended_action": {"type": "string", "enum": list(ACTIONS)},
        "action_evidence_ids": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
}


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    evidence_ids: list[str]


class CaseSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claims: list[Claim]
    recommended_action: Literal[ACTIONS]
    action_evidence_ids: list[str]
    confidence: Literal["low", "medium", "high"]


def _days(secs) -> str:
    if secs is None or (isinstance(secs, float) and math.isnan(secs)):
        return "none"
    return f"{secs / 86400:.1f} days" if secs >= 86400 else f"{secs / 3600:.1f} hours"


def _pct(x) -> str:
    pct = 100 * float(x)
    return "less than 0.0001%" if pct < 1e-4 else f"{pct:.2g}%" if pct < 1 else f"{pct:.1f}%"


def _yes(x) -> str:
    return "yes" if bool(x) else "no"


def _seen(x) -> str:
    return "no (first time)" if bool(x) else "yes (seen before)"


FEATURES = [
    ("new_country_ok", "the account has logged in successfully from this country before", _seen),
    ("new_asn_ok", "the account has logged in successfully from this network (ASN) before", _seen),
    ("new_subnet24_ok", "the account has logged in successfully from this /24 IP range before", _seen),
    ("new_ip_ok", "the account has logged in successfully from this IP before", _seen),
    ("new_device_ok", "the account has logged in successfully with this browser / OS / device combination before", _seen),
    ("new_country", "the account has had any login attempt (failed attempts included) from this country before", _seen),
    ("new_device", "the account has had any login attempt (failed attempts included) with this browser / OS / device combination before", _seen),
    ("user_prior_logins", "earlier logins by the account", lambda v: f"{int(v)}"),
    ("user_prior_successes", "earlier successful logins by the account", lambda v: f"{int(v)}"),
    ("secs_since_prev_success", "time since the account's previous successful login", _days),
    ("user_fails_1h", "failed logins by the account in the previous hour", lambda v: f"{int(v)}"),
    ("user_fails_24h", "failed logins by the account in the previous 24 hours", lambda v: f"{int(v)}"),
    ("lr_score_ok", "likelihood-ratio score against the account's successful logins (above 0 = more typical of attacks than of this account; below 0 = more typical of this account)", lambda v: f"{v:.1f}"),
    ("asn_freq", "site-wide share of all users' earlier logins that came from this network (not about this account)", _pct),
    ("asn_attack_rate", "share of this network's earlier logins that came from known attack IPs", _pct),
    ("asn_ato_prior", "confirmed takeovers from this network at least 7 days earlier", lambda v: f"{int(v)}"),
    ("subnet_ato_prior", "confirmed takeovers from this /24 IP range at least 7 days earlier", lambda v: f"{int(v)}"),
    ("ip_ato_prior", "confirmed takeovers from this IP at least 7 days earlier", lambda v: f"{int(v)}"),
    ("ip_users_24h", "distinct accounts that used this IP in the previous 24 hours", lambda v: f"{int(v)}"),
    ("ip_logins_24h", "logins from this IP in the previous 24 hours", lambda v: f"{int(v)}"),
]


def _login_line(r) -> str:
    place = ", ".join(str(x) for x in (r.get("city"), r.get("country")) if isinstance(x, str) and x)
    return (f"{pd.Timestamp(r['ts']):%Y-%m-%d %H:%M} UTC | {place or 'unknown location'} | ASN {r['asn']} | "
            f"{privacy.ip(r['ip'])} | {r['browser']} on {r['os']} ({r['device_type']}) | "
            f"password correct: {_yes(r['login_successful'])}")


def packet(alert: pd.Series, feats: pd.Series, history: pd.DataFrame, thresholds: tuple[float, float]) -> dict:
    band = ("at or above the BLOCK threshold" if alert["action"] == "BLOCK"
            else "at or above the CHALLENGE threshold and below the BLOCK threshold")
    ev = {"A1": (f"Model decision: {alert['action']} with calibrated takeover probability {alert['score']:.6f}, {band} "
                 f"(policy thresholds: CHALLENGE at {thresholds[0]:.6f} or above, BLOCK at {thresholds[1]:.6f} or above); "
                 f"account {privacy.user(alert['user_id'])}")}
    for i, r in enumerate(alert["reasons"], 1):
        ev[f"R{i}"] = f"Model reason {i}: {r}"
    for i, (col, desc, fmt) in enumerate(FEATURES, 1):
        ev[f"F{i}"] = f"{desc}: {fmt(feats[col])}"
    rows = history.sort_values("ts", ascending=False)
    current = rows[rows["ts"] == alert["event_ts"]].head(1)
    earlier = rows[rows["ts"] < alert["event_ts"]].head(HISTORY)
    if len(current):
        ev["L0"] = "This login: " + _login_line(current.iloc[0])
    for i, (_, r) in enumerate(earlier.iterrows(), 1):
        ev[f"L{i}"] = f"Earlier login {i} (most recent first): " + _login_line(r)
    if not len(earlier):
        ev["L1"] = "Earlier logins: none (first login of this account)"
    total, shown = int(feats["user_prior_logins"]), len(earlier)
    if shown == 0:
        ev["H1"] = "History listed: the account has no earlier logins"
    elif shown >= total:
        ev["H1"] = f"History listed: all {total} earlier logins of the account are listed, as L1 to L{shown} (complete history)"
    else:
        ev["H1"] = f"History listed: only the {shown} most recent of the account's {total} earlier logins are listed, as L1 to L{shown}"
    case_id = "C-" + hashlib.sha256(str(int(alert["login_id"])).encode()).hexdigest()[:8]
    return {"case_id": case_id, "login_id": int(alert["login_id"]), "evidence": ev}


def prompt(p: dict) -> str:
    lines = "\n".join(f"[{k}] {v}" for k, v in p["evidence"].items())
    return f"Case {p['case_id']}\n\nEvidence:\n{lines}\n\nWrite the case summary."


ID_TOKENS = re.compile(r"\b(?:[ARFLH]\d+|C-[0-9a-f]{8}|(?:U|IP|NET)-[0-9a-f]{10})\b")
NUMBER = re.compile(r"\d+(?:[.,]\d+)*")


def _numbers(text: str) -> list[str]:
    return [n.replace(",", "") for n in NUMBER.findall(ID_TOKENS.sub(" ", text))]


def _supported(n: str, pool: list[str]) -> bool:
    if n.count(".") > 1:
        return n in pool
    x = float(n)
    return any(m.count(".") <= 1 and abs(x - float(m)) <= max(1e-9, 0.01 * abs(float(m))) for m in pool)


def ground(summary: CaseSummary, p: dict) -> dict:
    ev = p["evidence"]
    kept, removed = [], []
    for c in summary.claims:
        cites = [i for i in c.evidence_ids if i in ev]
        if not cites:
            removed.append({**c.model_dump(), "reason": "no valid citation"})
            continue
        pool = [x for i in cites for x in _numbers(ev[i])]
        missing = [n for n in _numbers(c.text) if not _supported(n, pool)]
        if missing:
            removed.append({**c.model_dump(), "reason": f"number not in cited evidence: {missing}"})
            continue
        kept.append({"text": c.text, "evidence_ids": cites})
    return {"claims": kept, "removed": removed, "recommended_action": summary.recommended_action,
            "action_evidence_ids": [i for i in summary.action_evidence_ids if i in ev],
            "confidence": summary.confidence}


PROVIDERS = {"gemini": "gemini-3.6-flash", "claude": MODEL}
KEYS = {"gemini": "GEMINI_API_KEY", "claude": "ANTHROPIC_API_KEY"}


def _client(provider: str):
    load_dotenv(ROOT / ".env")
    key = os.environ.get(KEYS[provider])
    if not key:
        raise RuntimeError(f"{KEYS[provider]} is not set in .env")
    if provider == "gemini":
        from google import genai
        return genai.Client(api_key=key, http_options={"timeout": 120_000, "retry_options": {"attempts": 1}})
    import anthropic
    return anthropic.Anthropic()


def _cost(model: str, tokens_in, tokens_out) -> float:
    if model not in PRICES:
        return 0.0
    pin, pout = PRICES[model]
    return ((tokens_in or 0) * pin + (tokens_out or 0) * pout) / 1e6


def _strip(schema):
    if isinstance(schema, dict):
        return {k: _strip(v) for k, v in schema.items() if k != "additionalProperties"}
    if isinstance(schema, list):
        return [_strip(v) for v in schema]
    return schema


def _call_claude(client, text: str, model: str, effort: str) -> dict:
    response = client.beta.messages.create(
        model=model,
        max_tokens=8000,
        system=SYSTEM,
        messages=[{"role": "user", "content": text}],
        output_config={"effort": effort, "format": {"type": "json_schema", "schema": SCHEMA}},
        **({"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"} if model in FALLBACK_MODELS else {}),
    )
    raw = next((b.text for b in response.content if b.type == "text"), None)
    ok = response.stop_reason != "refusal" and raw is not None
    return {"model": response.model, "status": response.stop_reason, "raw": raw if ok else None,
            "input_tokens": response.usage.input_tokens, "output_tokens": response.usage.output_tokens,
            "cost_usd": _cost(response.model, response.usage.input_tokens, response.usage.output_tokens),
            "request_id": response._request_id}


def _call_gemini(client, text: str, model: str, effort: str) -> dict:
    interaction = client.interactions.create(
        model=model,
        system_instruction=SYSTEM,
        input=text,
        store=False,
        generation_config={"thinking_level": effort, "max_output_tokens": 8000},
        response_format={"type": "text", "mime_type": "application/json", "schema": _strip(SCHEMA)},
        timeout=CALL_BUDGET_S,
    )
    u = interaction.usage
    return {"model": model, "status": interaction.status,
            "raw": interaction.output_text if interaction.status == "completed" else None,
            "input_tokens": getattr(u, "total_input_tokens", None),
            "output_tokens": getattr(u, "total_output_tokens", None),
            "thought_tokens": getattr(u, "total_thought_tokens", None),
            "cost_usd": 0.0, "request_id": interaction.id}


CALLS = {"claude": _call_claude, "gemini": _call_gemini}
CALL_BUDGET_S = 180
HARD_DEADLINE_S = 240


class DeadlineTimeout(Exception):
    pass


def _deadline(fn, seconds: float):
    box = {}

    def target():
        try:
            box["value"] = fn()
        except Exception as exc:
            box["error"] = exc
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise DeadlineTimeout(f"no response within {seconds:.0f}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def _retryable(exc: Exception) -> bool:
    code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if code == 429 or (isinstance(code, int) and code >= 500):
        return True
    return any(word in type(exc).__name__ for word in ("Timeout", "Connection", "Continuation"))


def _with_retries(fn, attempts: int = 4, base: float = 15.0):
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:
            code = getattr(exc, "status_code", None) or type(exc).__name__
            if i == attempts - 1 or not _retryable(exc):
                raise
            wait = base * 2 ** i
            print(f"    HTTP {code}; retrying in {wait:.0f}s", flush=True)
            time.sleep(wait)


def narrate(client, p: dict, provider: str = "gemini", model: str | None = None, effort: str = "low") -> dict:
    model = model or PROVIDERS[provider]
    t0 = time.perf_counter()
    meta = _with_retries(lambda: _deadline(lambda: CALLS[provider](client, prompt(p), model, effort), HARD_DEADLINE_S))
    out = {"case_id": p["case_id"], "login_id": p["login_id"], "provider": provider, "effort": effort,
           "prompt_version": PROMPT_VERSION,
           "seconds": round(time.perf_counter() - t0, 2), **meta}
    if out["raw"] is None:
        out["error"] = f"no summary (status {out['status']})"
        return out
    try:
        out["grounded"] = ground(CaseSummary.model_validate_json(out["raw"]), p)
    except ValueError as exc:
        out["error"] = f"invalid JSON: {exc}"
    return out


def log_path():
    return path(load_config()["data"]["models_dir"]).parent / "ops" / "narratives.jsonl"


def thresholds() -> tuple[float, float]:
    calib = json.loads((path(load_config()["data"]["models_dir"]) / f"{load_config()['models']['ato']}_calibration.json").read_text())
    return calib["t_challenge"], calib["t_block"]


def cases(limit: int | None = None, seed: int = 0, alerts: pd.DataFrame | None = None) -> list[dict]:
    alerts = casework.alerts() if alerts is None else alerts
    if limit:
        alerts = alerts.sample(min(limit, len(alerts)), random_state=seed)
    feats = casework.alert_features(alerts).set_index("login_id")
    t = thresholds()
    out = []
    for _, a in alerts.iterrows():
        hist = casework.user_history(int(a["user_id"]), a["event_ts"], limit=HISTORY + 5)
        out.append(packet(a, feats.loc[int(a["login_id"])], hist, t))
    return out


DASHBOARD_MODEL = "claude-haiku-5-5"


def dashboard_path():
    return log_path().with_name("narratives_dashboard.jsonl")


def cached(login_id: int, ato_model: str) -> dict | None:
    f = dashboard_path()
    if not f.exists():
        return None
    hit = None
    for line in f.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if (r["login_id"], r.get("ato_model"), r.get("prompt_version")) == (login_id, ato_model, PROMPT_VERSION):
                hit = r
    return hit


def summarize_alert(alert: pd.Series, client=None, model: str = DASHBOARD_MODEL, effort: str = "low") -> dict:
    hit = cached(int(alert["login_id"]), alert["model_version"])
    if hit:
        return hit
    p = cases(alerts=alert.to_frame().T.astype({"login_id": int, "user_id": int}))[0]
    r = narrate(client or _client("claude"), p, "claude", model, effort)
    r.update(evidence=p["evidence"], ato_model=alert["model_version"],
             logged_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    if "error" not in r:
        with dashboard_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(r) + "\n")
    return r


def estimate(n: int, provider: str = "gemini", model: str | None = None) -> None:
    model = model or PROVIDERS[provider]
    sample = cases(limit=min(n, 20))
    chars = [len(SYSTEM) + len(prompt(p)) + len(json.dumps(SCHEMA)) for p in sample]
    tokens_in = sum(chars) / len(chars) / 3.5
    tokens_out = 900
    per_case = _cost(model, tokens_in, tokens_out)
    note = "" if model in PRICES else " (free tier: no charge within its rate limits)"
    print(f"~{tokens_in:,.0f} input + ~{tokens_out} output tokens per case on {model}: "
          f"~${per_case:.4f} per case, ~${per_case * n:.2f} for {n} cases{note}")


def run(limit: int | None, provider: str, model: str | None, effort: str, rpm: float) -> None:
    model = model or PROVIDERS[provider]
    client = _client(provider)
    out_file = log_path()
    done = set()
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done.add((r["login_id"], r["model"], r.get("prompt_version", 1)))
    todo = [p for p in cases(limit) if (p["login_id"], model, PROMPT_VERSION) not in done]
    print(f"{len(todo)} cases to narrate with {model} ({len(done)} results already in {out_file.name})", flush=True)
    gap = 60.0 / rpm if rpm else 0.0
    total, last = 0.0, 0.0
    with out_file.open("a", encoding="utf-8") as f:
        for i, p in enumerate(todo, 1):
            wait = last + gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            last = time.monotonic()
            try:
                r = narrate(client, p, provider, model, effort)
            except Exception as exc:
                print(f"  {i}/{len(todo)} {p['case_id']}: failed after retries ({type(exc).__name__}: {str(exc)[:120]}); skipped", flush=True)
                continue
            r["evidence"] = p["evidence"]
            r["logged_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            f.write(json.dumps(r) + "\n")
            f.flush()
            total += r["cost_usd"]
            kept = len(r.get("grounded", {}).get("claims", []))
            removed = len(r.get("grounded", {}).get("removed", []))
            print(f"  {i}/{len(todo)} {p['case_id']}: {kept} claims kept, {removed} removed "
                  f"{r.get('error', '')} ${r['cost_usd']:.4f} ({r['seconds']}s)", flush=True)
    print(f"total ${total:.2f}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["show", "estimate", "run"])
    ap.add_argument("--provider", choices=list(PROVIDERS), default="gemini")
    ap.add_argument("--model", default=None)
    ap.add_argument("--effort", default="low")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--rpm", type=float, default=None, help="max requests per minute (default 5 for gemini, unlimited for claude)")
    a = ap.parse_args()
    if a.cmd == "show":
        print(SYSTEM, "\n\n---\n", prompt(cases(limit=1)[0]))
    elif a.cmd == "estimate":
        estimate(a.limit or 100, a.provider, a.model)
    else:
        rpm = a.rpm if a.rpm is not None else (5.0 if a.provider == "gemini" else 0.0)
        run(a.limit, a.provider, a.model, a.effort, rpm)
