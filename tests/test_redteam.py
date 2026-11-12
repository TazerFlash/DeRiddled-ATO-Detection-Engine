"""Red-team blind spot: an attacker's own failed attempts must not make their country, network or device look familiar; plus generator shape checks."""
import numpy as np
import pandas as pd

from deriddled.redteam import Scenario, generate
from deriddled.state import OnlineState, prepare


def _event(i, ts, country, asn, ip, ok, browser="Chrome 79", os_="Windows 10"):
    return prepare({"login_id": i, "ts": pd.Timestamp(ts), "user_id": 7, "ip": ip, "asn": asn, "country": country,
                    "browser": browser, "os": os_, "device_type": "desktop", "rtt_ms": None, "login_successful": ok,
                    "is_attack_ip": False, "is_ato": False, "is_non_account": False})


def test_failed_attempts_do_not_count_as_familiar():
    s = OnlineState()
    history = [_event(i, f"2020-09-0{i} 10:00", "NO", 29695, "10.0.0.1", True) for i in range(1, 4)]
    attack = [_event(10 + j, f"2020-09-05 03:0{j}", "RO", 3280, f"10.9.9.{j}", j == 2, "Chrome 85", "Linux") for j in range(3)]
    feats = [s.process_group([e])[0] for e in history + attack]
    take = feats[-1]
    assert not take["new_country"] and not take["new_asn"] and not take["new_device"]
    assert take["new_country_ok"] and take["new_asn_ok"] and take["new_device_ok"] and take["new_subnet24_ok"]
    assert take["lr_score_ok"] > take["lr_score"]
    assert not feats[2]["new_country_ok"] and not feats[2]["new_device_ok"]


def test_success_counts_after_takeover():
    s = OnlineState()
    for e in [_event(1, "2020-09-01", "NO", 1, "10.0.0.1", True), _event(2, "2020-09-02", "RO", 2, "10.9.0.1", True)]:
        s.process_group([e])
    f = s.process_group([_event(3, "2020-09-03", "RO", 2, "10.9.0.2", False)])[0]
    assert not f["new_country_ok"] and not f["new_asn_ok"] and f["new_ip_ok"]


def _pools():
    subnets = {29695: pd.DataFrame({"asn": [29695], "subnet": ["10.1.2"], "country": ["NO"]}),
               3280: pd.DataFrame({"asn": [3280], "subnet": ["10.9.9"], "country": ["RO"]})}
    return {"local": pd.DataFrame({"country": ["NO", "RO"], "asn": [29695, 3280], "users": [1000, 300]}),
            "rare": np.array([3280]), "attack": np.array([3280]),
            "devices": pd.DataFrame({"browser": ["Safari 14"], "os": ["iOS 14"], "device_type": ["mobile"], "users": [9]}),
            "subnets": subnets, "rtt": np.array([np.nan, 120.0])}


def test_generator_shape():
    sc = Scenario(name="t", description="", rationale="", victims=2, origin="foreign_country", foreign_country="RO",
                  network="common_local_asn", ip="fresh_ip_per_attempt", ip_pool_size=None, device="mimic_victim",
                  fixed_browser=None, fixed_os=None, fixed_device_type=None, failed_attempts_before_success=3,
                  minutes_between_attempts=30, timing="night", ips_on_threat_list=False)
    vics = pd.DataFrame({"user_id": [1, 2], "country": ["NO", "NO"], "asn": [29695, 29695], "subnet": ["10.1.2", "10.1.2"],
                         "device": ["Chrome 79\x1fWindows 10\x1fdesktop"] * 2, "hour": [9, 20], "ips": [["10.1.2.3"], ["10.1.2.4"]]})
    T = pd.Timestamp("2020-09-10")
    ev = generate(sc, vics, _pools(), T, np.random.default_rng(0), -1)
    assert len(ev) == 8 and ev.groupby("user_id").size().eq(4).all()
    assert ev.groupby("user_id").login_successful.sum().eq(1).all() and (ev.is_ato == ev.login_successful).all()
    assert (ev.country == "RO").all() and (ev.asn == 3280).all() and ev.ip.str.startswith("10.9.9.").all()
    assert (ev.browser == "Chrome 79").all() and ev.ts.between(T, T + pd.Timedelta(hours=24)).all()
    assert ev.login_id.is_unique and (ev.login_id < 0).all()
    last = ev.sort_values("ts").groupby("user_id").tail(1)
    assert last.login_successful.all()
