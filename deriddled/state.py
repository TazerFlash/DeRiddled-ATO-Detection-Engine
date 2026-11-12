"""Online feature state: computes the main ATO model's features one timestamp group at a time, matching features.sql."""
import math
import re
from collections import Counter, defaultdict, deque

import pandas as pd

from deriddled.config import load_config

MINUTE = 60_000_000
HOUR = 60 * MINUTE
DAY = 24 * HOUR
LR_KEYS = ("ip", "asn", "country", "ua")
USER_KEYS = ("country", "asn", "device_key", "ip", "subnet", "ua")
SUBNET_RE = re.compile(r"^(\d+\.\d+\.\d+)\.")


def subnet24(ip: str) -> str:
    m = SUBNET_RE.match(ip or "")
    return m.group(1) if m else ""


def concat_ws(*parts) -> str:
    return " | ".join(str(p) for p in parts if p is not None and not (isinstance(p, float) and math.isnan(p)))


def to_us(ts) -> int:
    return pd.Timestamp(ts).value // 1000


def prepare(event: dict) -> dict:
    e = dict(event)
    e["t"] = to_us(e["ts"])
    e["asn"] = str(e["asn"])
    e["subnet"] = subnet24(e["ip"])
    e["ua"] = concat_ws(e.get("browser"), e.get("os"))
    e["device_key"] = concat_ws(e.get("browser"), e.get("os"), e.get("device_type"))
    return e


class Window:
    """Events on one key in the last 24 h: logins, failures and distinct users."""

    def __init__(self):
        self.q = deque()
        self.users = Counter()
        self.fails = 0

    def add(self, t: int, user, failed: bool) -> None:
        self.q.append((t, user, failed))
        self.users[user] += 1
        self.fails += failed

    def expire(self, cutoff: int) -> None:
        while self.q and self.q[0][0] < cutoff:
            _, user, failed = self.q.popleft()
            self.users[user] -= 1
            if not self.users[user]:
                del self.users[user]
            self.fails -= failed


class OnlineState:
    def __init__(self):
        rep = load_config()["reputation"]
        self.delay = int(rep["label_delay_days"]) * DAY
        self.m, self.p0 = float(rep["m"]), float(rep["p0"])
        self.global_n = 0
        self.global_attack = 0
        self.vocab = {k: 0 for k in LR_KEYS}
        self.seen_value = {k: set() for k in LR_KEYS}
        self.pop = {k: defaultdict(lambda: [0, 0, 0]) for k in ("ip", "asn", "country", "ua")}
        self.user = defaultdict(lambda: {"n": 0, "succ": 0, "last": None, "last_succ": None, "recent": deque(),
                                         "values": {k: Counter() for k in USER_KEYS},
                                         "ok": {k: Counter() for k in USER_KEYS}})
        self.win = {k: defaultdict(Window) for k in ("ip", "subnet", "asn")}
        self.rep = {k: defaultdict(lambda: [0, 0]) for k in ("asn", "ip", "subnet")}
        self.pending = deque()
        self.group = []

    def features(self, e: dict) -> dict:
        t = e["t"]
        u = self.user[e["user_id"]]
        while u["recent"] and u["recent"][0][0] < t - DAY:
            u["recent"].popleft()
        logins_1m = sum(1 for ts, _ in u["recent"] if ts >= t - MINUTE)
        logins_1h = sum(1 for ts, _ in u["recent"] if ts >= t - HOUR)
        fails_1h = sum(f for ts, f in u["recent"] if ts >= t - HOUR)
        logins_24h, fails_24h = len(u["recent"]), sum(f for _, f in u["recent"])
        for k in self.win:
            self.win[k][e[k]].expire(t - DAY)
        asn_n, asn_att, asn_fail = self.pop["asn"][e["asn"]]
        ip_n, ip_att, ip_fail = self.pop["ip"][e["ip"]]
        g = self.global_n
        ts = pd.Timestamp(e["ts"])

        lr = lr_ok = 0.0
        for k in LR_KEYS:
            v = self.vocab[k]
            n, att, _ = self.pop[k][e[k]]
            p_pop = (n + 1) / (g + v + 1)
            p_att = math.log((att + 1) / (self.global_attack + v + 1))
            lr += p_att - math.log((u["values"][k][e[k]] + p_pop) / (u["n"] + 1))
            lr_ok += p_att - math.log((u["ok"][k][e[k]] + p_pop) / (u["succ"] + 1))

        rep = {}
        for k in ("asn", "ip", "subnet"):
            n, kk = self.rep[k][e[k]]
            rep[f"{k}_ato_prior"] = kk
            rep[f"{k}_ato_rate"] = (kk + self.m * self.p0) / (n + self.m)

        return {
            "hour": ts.hour, "weekday": ts.isoweekday(), "rtt_present": e.get("rtt_ms") is not None and not pd.isna(e.get("rtt_ms")),
            "user_prior_logins": u["n"], "user_prior_successes": u["succ"],
            "secs_since_prev": math.nan if u["last"] is None else (t - u["last"]) / 1e6,
            "secs_since_prev_success": math.nan if u["last_succ"] is None else (t - u["last_succ"]) / 1e6,
            "user_logins_1m": logins_1m, "user_logins_1h": logins_1h, "user_fails_1h": fails_1h,
            "user_logins_24h": logins_24h, "user_fails_24h": fails_24h,
            "user_fail_ratio_24h": fails_24h / logins_24h if logins_24h else math.nan,
            "new_country": u["values"]["country"][e["country"]] == 0,
            "new_asn": u["values"]["asn"][e["asn"]] == 0,
            "new_device": u["values"]["device_key"][e["device_key"]] == 0,
            "new_ip": u["values"]["ip"][e["ip"]] == 0,
            "new_subnet24": u["values"]["subnet"][e["subnet"]] == 0,
            "asn_freq": asn_n / g if g else math.nan,
            "ua_freq": self.pop["ua"][e["ua"]][0] / g if g else math.nan,
            "asn_attack_rate": (asn_att + 1) / (asn_n + 2), "asn_fail_rate": (asn_fail + 1) / (asn_n + 2),
            "ip_prior_logins": ip_n, "ip_prior_attack_ip": ip_att, "ip_prior_fails": ip_fail,
            "ip_logins_24h": len(self.win["ip"][e["ip"]].q), "ip_fails_24h": self.win["ip"][e["ip"]].fails,
            "ip_users_24h": len(self.win["ip"][e["ip"]].users),
            "subnet_logins_24h": len(self.win["subnet"][e["subnet"]].q),
            "subnet_users_24h": len(self.win["subnet"][e["subnet"]].users),
            "asn_users_24h": len(self.win["asn"][e["asn"]].users),
            "new_country_ok": u["ok"]["country"][e["country"]] == 0,
            "new_asn_ok": u["ok"]["asn"][e["asn"]] == 0,
            "new_device_ok": u["ok"]["device_key"][e["device_key"]] == 0,
            "new_ip_ok": u["ok"]["ip"][e["ip"]] == 0,
            "new_subnet24_ok": u["ok"]["subnet"][e["subnet"]] == 0,
            "lr_score": lr, "lr_score_ok": lr_ok, **rep, "device_type": e.get("device_type"),
        }

    def update(self, e: dict) -> None:
        t, failed, attack = e["t"], not e["login_successful"], bool(e["is_attack_ip"])
        self.global_n += 1
        self.global_attack += attack
        for k in ("ip", "asn", "country", "ua"):
            c = self.pop[k][e[k]]
            c[0] += 1
            c[1] += attack
            c[2] += failed
        for k in LR_KEYS:
            if e[k] not in self.seen_value[k]:
                self.seen_value[k].add(e[k])
                self.vocab[k] += 1
        for k in self.win:
            self.win[k][e[k]].add(t, e["user_id"], failed)
        self.pending.append((t, e["asn"], e["ip"], e["subnet"], bool(e["is_ato"])))
        if not e["is_non_account"]:
            u = self.user[e["user_id"]]
            u["n"] += 1
            u["succ"] += not failed
            u["last"] = t
            if not failed:
                u["last_succ"] = t
            u["recent"].append((t, failed))
            for k in u["values"]:
                u["values"][k][e[k]] += 1
                if not failed:
                    u["ok"][k][e[k]] += 1

    def release(self, t: int) -> None:
        while self.pending and self.pending[0][0] <= t - self.delay:
            _, asn, ip, sub, ato = self.pending.popleft()
            for k, v in (("asn", asn), ("ip", ip), ("subnet", sub)):
                self.rep[k][v][0] += 1
                self.rep[k][v][1] += ato

    def score_stream(self, event: dict) -> tuple[dict, dict]:
        """Streaming version of process_group: same-timestamp events are buffered and folded in when time advances."""
        e = prepare(event)
        if self.group and e["t"] != self.group[0]["t"]:
            self.flush()
        if not self.group:
            self.release(e["t"])
        f = self.features(e)
        self.group.append(e)
        return e, f

    def flush(self) -> None:
        for e in self.group:
            self.update(e)
        self.group = []

    def process_group(self, events: list[dict]) -> list[dict]:
        """Score every event sharing one timestamp, then add them all to the state."""
        self.release(events[0]["t"])
        out = [self.features(e) for e in events]
        for e in events:
            self.update(e)
        return out
