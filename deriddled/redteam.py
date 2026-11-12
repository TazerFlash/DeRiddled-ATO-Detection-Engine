"""Red-team simulator: an LLM writes attack scenarios as parameters, a generator turns them into synthetic logins on real victim accounts, and the online scorer replays them among real traffic to measure recall per scenario."""
import argparse
import json
import time
from typing import Literal

import numpy as np
import pandas as pd
import xgboost as xgb
from pydantic import BaseModel, ConfigDict, Field

from deriddled.config import ROOT, connect, load_config, path
from deriddled.evaluate import wilson
from deriddled.narrator import FALLBACK_MODELS, _client, _cost, _with_retries
from deriddled.parity import _logins, replay, replay_events, warm_start
from deriddled.train import matrix

SCENARIOS = ROOT / "eval" / "redteam_scenarios.json"
WRITER = "claude-sonnet-5-5"
OUT = path("data/ops/redteam")
VALID_WINDOWS = ("2020-09-10", "2020-09-13")
SYNTHETIC_ID = -1_000_000_000


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str
    rationale: str
    victims: int = Field(ge=1, le=60)
    origin: Literal["victim_country", "foreign_country"]
    foreign_country: str | None
    network: Literal["victim_asn", "common_local_asn", "rare_asn", "attack_listed_asn"]
    ip: Literal["victim_subnet_new_ip", "fresh_ip_per_attempt", "shared_pool"]
    ip_pool_size: int | None
    device: Literal["mimic_victim", "common_device", "fixed"]
    fixed_browser: str | None
    fixed_os: str | None
    fixed_device_type: Literal["desktop", "mobile", "tablet", "bot", "unknown"] | None
    failed_attempts_before_success: int = Field(ge=0, le=30)
    minutes_between_attempts: float = Field(ge=0.01, le=600)
    timing: Literal["victim_usual_hour", "night", "random"]
    ips_on_threat_list: bool


class ScenarioSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenarios: list[Scenario]


def _nullable(t):
    return {"type": [t, "null"]}


SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["scenarios"],
    "properties": {"scenarios": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": list(Scenario.model_fields),
        "properties": {
            "name": {"type": "string"}, "description": {"type": "string"}, "rationale": {"type": "string"},
            "victims": {"type": "integer"},
            "origin": {"type": "string", "enum": ["victim_country", "foreign_country"]},
            "foreign_country": _nullable("string"),
            "network": {"type": "string", "enum": ["victim_asn", "common_local_asn", "rare_asn", "attack_listed_asn"]},
            "ip": {"type": "string", "enum": ["victim_subnet_new_ip", "fresh_ip_per_attempt", "shared_pool"]},
            "ip_pool_size": _nullable("integer"),
            "device": {"type": "string", "enum": ["mimic_victim", "common_device", "fixed"]},
            "fixed_browser": _nullable("string"), "fixed_os": _nullable("string"),
            "fixed_device_type": {"anyOf": [{"type": "string", "enum": ["desktop", "mobile", "tablet", "bot", "unknown"]},
                                            {"type": "null"}]},
            "failed_attempts_before_success": {"type": "integer"},
            "minutes_between_attempts": {"type": "number"},
            "timing": {"type": "string", "enum": ["victim_usual_hour", "night", "random"]},
            "ips_on_threat_list": {"type": "boolean"},
        }}}},
}

WRITER_SYSTEM = """You are a red-team analyst testing an account-takeover detector for a single sign-on service. Most users are in Norway; the rest are spread across many countries. Real takeovers in the training data were mostly one campaign from Romania using an unusual Chrome build.

The detector scores every login with these signals:
- novelty for the account: first time seen country, network (ASN), /24 IP range, IP, or browser+OS+device combination
- a likelihood-ratio score: how much more typical the IP, ASN, country and browser+OS are of attack traffic than of this account's own history
- popularity: share of all logins from this ASN and from this browser+OS
- velocity: the account's logins and failures in the last minute, hour and 24 hours; time since its previous login and previous successful login
- shared infrastructure in the last 24 hours: logins, failures and distinct accounts per IP, per /24 range and per ASN
- threat intelligence: share of this IP's and ASN's earlier logins that came from known attack IPs
- takeover history: confirmed takeovers from this ASN, /24 range and IP at least 7 days earlier
- time of day, weekday, device type, and whether round-trip time was measured

Write exactly 5 attack scenarios as parameters for a simulator. Each scenario is one attacker campaign against several accounts; each victim gets some failed attempts and then one successful takeover login. Make them realistic and diverse: cover cheap noisy attacks and careful ones, and design at least two specifically to evade the signals above (for example by blending into the victim's own country, network and device). In rationale, name which signals the scenario is meant to trigger or evade. Use 30 victims per scenario. Parameter notes:
- origin foreign_country needs foreign_country as an ISO-2 code; otherwise set it to null.
- network: victim_asn = the victim's own usual network; common_local_asn = a popular network in the origin country (residential proxies); rare_asn = a small network few users use (rented servers); attack_listed_asn = a network dominated by known attack IPs.
- ip: victim_subnet_new_ip = a new IP inside the victim's usual /24 range (only sensible with victim_asn); fresh_ip_per_attempt; shared_pool = all attempts in the campaign rotate over ip_pool_size IPs (otherwise ip_pool_size is null).
- device: mimic_victim copies the victim's usual browser, OS and device; common_device = a popular combination; fixed needs fixed_browser (like 'Chrome 85.0.4183.83'), fixed_os (like 'Windows 10') and fixed_device_type; otherwise those are null.
- minutes_between_attempts is the gap between one victim's consecutive attempts; total time per victim must stay under 20 hours."""


def write_scenarios(model: str = WRITER, effort: str = "medium") -> ScenarioSet:
    client = _client("claude")
    response = _with_retries(lambda: client.beta.messages.create(
        model=model, max_tokens=16000, system=WRITER_SYSTEM,
        messages=[{"role": "user", "content": "Write the 5 scenarios."}],
        output_config={"effort": effort, "format": {"type": "json_schema", "schema": SCHEMA}},
        **({"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"} if model in FALLBACK_MODELS else {})))
    raw = next(b.text for b in response.content if b.type == "text")
    parsed = ScenarioSet.model_validate_json(raw)
    if SCENARIOS.exists():
        SCENARIOS.rename(SCENARIOS.with_name(f"redteam_scenarios_{time.strftime('%Y%m%d_%H%M%S')}.json"))
    SCENARIOS.write_text(json.dumps({"model": response.model, "written_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                     "cost_usd": _cost(response.model, response.usage.input_tokens, response.usage.output_tokens),
                                     **parsed.model_dump()}, indent=2), encoding="utf-8")
    print(f"wrote {SCENARIOS} ({response.model}, ${_cost(response.model, response.usage.input_tokens, response.usage.output_tokens):.4f})")
    return parsed


def load_scenarios(file=SCENARIOS) -> list[Scenario]:
    return ScenarioSet.model_validate(
        {"scenarios": json.loads(file.read_text(encoding="utf-8"))["scenarios"]}).scenarios


SUBNET = "regexp_extract(ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1)"


def victims(con, T: pd.Timestamp, n: int, seed: int) -> pd.DataFrame:
    L = _logins()
    return con.execute(f"""
        WITH cand AS (
            SELECT user_id FROM {L}
            WHERE ts >= TIMESTAMP '{T - pd.Timedelta(days=30)}' AND ts < TIMESTAMP '{T}' AND NOT is_non_account
            GROUP BY user_id HAVING SUM(login_successful::INT) >= 5 AND MAX(is_ato::INT) = 0
            ORDER BY hash(user_id + {seed}) LIMIT {n}),
        h AS (
            SELECT user_id, country, asn, ip, {SUBNET} AS subnet, browser, os, device_type, hour(ts) AS hr
            FROM {L} JOIN cand USING (user_id)
            WHERE ts >= TIMESTAMP '{T - pd.Timedelta(days=90)}' AND ts < TIMESTAMP '{T}' AND login_successful)
        SELECT user_id, mode(country ORDER BY country) AS country, mode(asn ORDER BY asn) AS asn,
               mode(subnet ORDER BY subnet) AS subnet,
               mode(concat_ws(chr(31), browser, os, device_type) ORDER BY concat_ws(chr(31), browser, os, device_type)) AS device,
               mode(hr ORDER BY hr) AS hour, list(DISTINCT ip ORDER BY ip) AS ips
        FROM h GROUP BY user_id ORDER BY hash(user_id + {seed})""").df()


def pools(con, T: pd.Timestamp) -> dict:
    L = _logins()
    since = f"ts >= TIMESTAMP '{T - pd.Timedelta(days=30)}' AND ts < TIMESTAMP '{T}'"
    local = con.execute(f"""SELECT country, asn, COUNT(DISTINCT user_id) AS users FROM {L}
                            WHERE {since} AND NOT is_non_account GROUP BY 1, 2 HAVING users >= 200 ORDER BY 1, 2""").df()
    rare = con.execute(f"""SELECT asn FROM {L} WHERE ts < TIMESTAMP '{T}' GROUP BY asn
                           HAVING COUNT(*) BETWEEN 5 AND 100 AND MAX(is_attack_ip::INT) = 0 AND MAX(is_ato::INT) = 0 ORDER BY asn""").df()["asn"]
    attack = con.execute(f"""SELECT asn FROM {L} WHERE {since} GROUP BY asn
                             HAVING COUNT(*) >= 500 AND AVG(is_attack_ip::INT) >= 0.5 ORDER BY asn""").df()["asn"]
    devices = con.execute(f"""SELECT browser, os, device_type, COUNT(DISTINCT user_id) AS users FROM {L}
                              WHERE {since} AND NOT is_non_account AND browser IS NOT NULL
                              GROUP BY 1, 2, 3 ORDER BY users DESC, 1, 2, 3 LIMIT 40""").df()
    asns = pd.DataFrame({"asn": pd.concat([local["asn"], rare, attack]).unique()})
    con.register("pool_asns", asns)
    subnets = con.execute(f"""SELECT asn, {SUBNET} AS subnet, mode(country) AS country FROM {L} JOIN pool_asns USING (asn)
                              WHERE ts < TIMESTAMP '{T}' AND {SUBNET} != '' GROUP BY 1, 2 ORDER BY 1, 2""").df()
    rtt = con.execute(f"""SELECT rtt_ms FROM {L} WHERE {since} AND NOT is_non_account
                          ORDER BY hash(login_id) LIMIT 20000""").df()["rtt_ms"]
    return {"local": local, "rare": rare.to_numpy(), "attack": attack.to_numpy(), "devices": devices,
            "subnets": {a: g for a, g in subnets.groupby("asn")}, "rtt": rtt.to_numpy()}


def _pick_asn(sc: Scenario, v, country: str, pl: dict, rng) -> int:
    if sc.network == "victim_asn":
        return int(v.asn)
    if sc.network == "common_local_asn":
        local = pl["local"][pl["local"].country == country]
        if len(local):
            return int(rng.choice(local.asn.to_numpy(), p=(local.users / local.users.sum()).to_numpy()))
        return int(rng.choice(pl["local"].asn.to_numpy()))
    return int(rng.choice(pl["rare"] if sc.network == "rare_asn" else pl["attack"]))


def _new_ip(subnet: str, taken: set, rng) -> str:
    for _ in range(50):
        ip = f"{subnet}.{rng.integers(1, 255)}"
        if ip not in taken:
            return ip
    return f"{subnet}.{rng.integers(1, 255)}"


def _ip_for(sc: Scenario, v, asn: int, pl: dict, rng) -> tuple[str, str]:
    subs = pl["subnets"].get(asn)
    if sc.ip == "victim_subnet_new_ip" and v.subnet:
        return _new_ip(v.subnet, set(v.ips), rng), None
    if subs is None or not len(subs):
        return f"{rng.integers(11, 223)}.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}", None
    row = subs.iloc[rng.integers(len(subs))]
    return _new_ip(row.subnet, set(v.ips), rng), row.country


def generate(sc: Scenario, vics: pd.DataFrame, pl: dict, T: pd.Timestamp, rng, first_id: int) -> pd.DataFrame:
    rows, next_id = [], first_id
    pool = None
    if sc.ip == "shared_pool":
        asn = _pick_asn(sc, vics.iloc[0], sc.foreign_country or vics.iloc[0].country, pl, rng)
        pool = [(*_ip_for(sc, vics.iloc[0], asn, pl, rng), asn) for _ in range(max(1, sc.ip_pool_size or 5))]
    countries = pl["local"].groupby("country").users.sum()
    for k, v in enumerate(vics.itertuples()):
        if sc.origin == "foreign_country":
            country = sc.foreign_country if sc.foreign_country in countries.index else None
            if country is None or country == v.country:
                other = countries.drop(v.country, errors="ignore")
                country = str(rng.choice(other.index.to_numpy(), p=(other / other.sum()).to_numpy()))
        else:
            country = v.country
        if sc.device == "mimic_victim" and v.device:
            browser, os_, dev = (v.device.split(chr(31)) + [None, None, None])[:3]
        elif sc.device == "fixed" and sc.fixed_browser:
            browser, os_, dev = sc.fixed_browser, sc.fixed_os, sc.fixed_device_type
        else:
            d = pl["devices"].iloc[rng.integers(len(pl["devices"]))]
            browser, os_, dev = d.browser, d.os, d.device_type
        n = sc.failed_attempts_before_success + 1
        gaps = rng.uniform(0.7, 1.3, n - 1) * sc.minutes_between_attempts
        span = pd.Timedelta(minutes=float(gaps.sum()))
        latest = pd.Timedelta(hours=23.5) - span
        if sc.timing == "victim_usual_hour" and v.hour is not None:
            start = pd.Timedelta(hours=int(v.hour), minutes=float(rng.uniform(0, 60)))
        elif sc.timing == "night":
            start = pd.Timedelta(hours=float(rng.uniform(1, 5)))
        else:
            start = pd.Timedelta(hours=float(rng.uniform(0, 24)))
        start = min(max(start, pd.Timedelta(minutes=5)), max(latest, pd.Timedelta(minutes=5)))
        times = T + start + pd.to_timedelta(np.concatenate([[0], np.cumsum(gaps)]), unit="m")
        asn = _pick_asn(sc, v, country, pl, rng)
        for j, ts in enumerate(times):
            if pool:
                ip, _, a = pool[rng.integers(len(pool))]
            else:
                ip, _ = _ip_for(sc, v, asn, pl, rng) if (j == 0 or sc.ip == "fresh_ip_per_attempt") else (ip, None)
                a = asn
            rtt = pl["rtt"][rng.integers(len(pl["rtt"]))]
            success = j == n - 1
            rows.append({"login_id": next_id, "ts": ts, "user_id": int(v.user_id), "ip": ip, "asn": int(a),
                         "country": country, "browser": browser, "os": os_, "device_type": dev,
                         "rtt_ms": None if pd.isna(rtt) else float(rtt), "login_successful": success,
                         "is_attack_ip": bool(sc.ips_on_threat_list), "is_ato": success, "is_non_account": False,
                         "scenario": sc.name, "victim": k})
            next_id -= 1
    return pd.DataFrame(rows)


def synthetic(con, T: pd.Timestamp, scenarios: list[Scenario], seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    pl = pools(con, T)
    vics = victims(con, T, sum(s.victims for s in scenarios), seed)
    parts, used, first = [], 0, SYNTHETIC_ID - seed * 10_000_000
    for sc in scenarios:
        part = generate(sc, vics.iloc[used:used + sc.victims], pl, T, rng, first)
        used += sc.victims
        first = int(part.login_id.min()) - 1 if len(part) else first
        parts.append(part)
    return pd.concat(parts, ignore_index=True)


def window_features(con, T: pd.Timestamp, syn: pd.DataFrame, hours: float = 24) -> tuple[pd.DataFrame, pd.DataFrame]:
    real = replay_events(con, T, hours)
    cols = list(real.columns)
    ev = pd.concat([real, syn[cols]], ignore_index=True).sort_values(["ts", "login_id"], kind="stable").reset_index(drop=True)
    ev["asn"] = ev["asn"].astype("int64")
    state = warm_start(con, T, ev)
    feats = replay(state, ev)
    return feats, ev


class Policy:
    def __init__(self, name: str | None = None):
        models = path(load_config()["data"]["models_dir"])
        self.name = name or load_config()["models"]["ato"]
        self.model = xgb.XGBClassifier()
        self.model.load_model(models / f"{self.name}.json")
        self.meta = json.loads((models / f"{self.name}_meta.json").read_text())
        self.cal = json.loads((models / f"{self.name}_calibration.json").read_text())

    def decide(self, feats: pd.DataFrame) -> pd.DataFrame:
        X = matrix(feats, self.meta["features"], self.meta["categories"])
        margin = self.model.predict(X, output_margin=True)
        p = np.interp(margin, self.cal["margin_grid"], self.cal["p_grid"])
        action = np.where(p >= self.cal["t_block"], "BLOCK", np.where(p >= self.cal["t_challenge"], "CHALLENGE", "ALLOW"))
        return pd.DataFrame({"login_id": feats["login_id"].to_numpy(), "p": p, "action": action})


def recall_table(scored: pd.DataFrame, syn: pd.DataFrame) -> pd.DataFrame:
    s = syn.merge(scored, on="login_id")
    s["flag"] = s["action"] != "ALLOW"
    rows = []
    for name, g in s.groupby("scenario", sort=False):
        take = g[g.is_ato]
        k, n = int(take.flag.sum()), len(take)
        acct = g.groupby(["window", "victim"]).flag.any()
        rows.append({"scenario": name, "takeovers": n, "stopped": k, "recall": k / n if n else np.nan,
                     "recall_ci": tuple(round(x, 3) for x in wilson(k, n)),
                     "blocked": int((take.action == "BLOCK").sum()),
                     "any_attempt_flagged": round(float(acct.mean()), 3),
                     "median_p_takeover": float(take.p.median())})
    return pd.DataFrame(rows)


def run(windows=VALID_WINDOWS, seed: int = 0, policies: tuple = (None,), scenario_file=SCENARIOS, tag: str = "valid") -> pd.DataFrame:
    scenarios = load_scenarios(scenario_file)
    con = connect()
    pols = [Policy(p) for p in policies]
    syn_all, scored = [], {p.name: [] for p in pols}
    real_alerts = {p.name: 0 for p in pols}
    for i, w in enumerate(windows):
        T = pd.Timestamp(w)
        t0 = time.time()
        syn = synthetic(con, T, scenarios, seed * 100 + i)
        feats, _ = window_features(con, T, syn)
        for p in pols:
            d = p.decide(feats)
            scored[p.name].append(d)
            real_alerts[p.name] += int(((d.login_id > 0) & (d.action != "ALLOW")).sum())
        syn_all.append(syn.assign(window=w))
        print(f"window {w}: {len(syn):,} synthetic + {int((feats.login_id > 0).sum()):,} real account logins, {time.time() - t0:.0f}s", flush=True)
    syn = pd.concat(syn_all, ignore_index=True)
    tables = []
    for p in pols:
        t = recall_table(pd.concat(scored[p.name], ignore_index=True), syn).assign(model=p.name)
        print(f"\n{p.name}: real-traffic alerts in the same windows {real_alerts[p.name]}\n{t.drop(columns='model').to_string(index=False)}")
        tables.append(t.assign(real_alerts=real_alerts[p.name]))
    out = pd.concat(tables, ignore_index=True)
    OUT.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT / f"recall_{tag}_seed{seed}.csv", index=False)
    syn.to_parquet(OUT / f"synthetic_{tag}_seed{seed}.parquet")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["write", "show", "run"])
    ap.add_argument("--model", default=WRITER)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--policies", nargs="*", default=[None])
    a = ap.parse_args()
    pd.set_option("display.width", 250)
    if a.cmd == "write":
        write_scenarios(a.model)
    if a.cmd in ("write", "show"):
        for s in load_scenarios():
            print(f"\n## {s.name}\n{s.description}\nrationale: {s.rationale}\n" + json.dumps(
                s.model_dump(exclude={"name", "description", "rationale"})))
    if a.cmd == "run":
        run(seed=a.seed, policies=tuple(a.policies))
