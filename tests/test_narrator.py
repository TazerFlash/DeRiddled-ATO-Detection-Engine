"""Narrator tests without API calls: grounding rules, schema validation, and no raw IPs or user IDs in prompts."""
import re

import pytest

from deriddled import casework, narrator
from deriddled.narrator import CaseSummary, ground

PACKET = {"case_id": "C-00000000", "login_id": 1, "evidence": {
    "A1": "Model decision: CHALLENGE with calibrated takeover probability 0.0045; account U-0123456789",
    "F6": "earlier logins by the account: 43",
    "F13": "share of this network's earlier logins that came from known attack IPs: 63.6%",
    "L0": "This login: 2020-09-10 18:19 UTC | IT | ASN 501775 | IP-abcdef0123 | Chrome 79.0.3945.192.218 on Mac OS X 10.14.6 (desktop)",
}}


def summary(*claims, action="contact_user_out_of_band", action_ids=("A1",)):
    return CaseSummary.model_validate({
        "claims": [{"text": t, "evidence_ids": list(ids)} for t, ids in claims],
        "recommended_action": action, "action_evidence_ids": list(action_ids), "confidence": "medium"})


def test_supported_claims_are_kept():
    g = ground(summary(("The account has 43 earlier logins.", ["F6"]),
                       ("75% of the network's earlier logins came from attack IPs.", ["F13"])), PACKET)
    assert [c["text"] for c in g["claims"]] == ["The account has 43 earlier logins."]
    assert g["removed"][0]["reason"].startswith("number not in cited evidence")


def test_uncited_and_unknown_citations_are_removed():
    g = ground(summary(("The login came from Italy.", []), ("It used a new phone.", ["F99"])), PACKET)
    assert g["claims"] == [] and {r["reason"] for r in g["removed"]} == {"no valid citation"}


def test_numbers_must_come_from_the_cited_item():
    g = ground(summary(("The account has 43 earlier logins.", ["F13"])), PACKET)
    assert g["claims"] == []


def test_ids_hashes_and_version_strings():
    g = ground(summary(("Login L0 for U-0123456789 used Chrome 79.0.3945.192.218 from ASN 501775 at 18:19.", ["L0"]),
                       ("It used Chrome 80.0.1.2.3.", ["L0"])), PACKET)
    assert len(g["claims"]) == 1 and "80.0.1.2.3" in g["removed"][0]["reason"]


def test_action_citations_filtered():
    g = ground(summary(("The account has 43 earlier logins.", ["F6"]), action_ids=("A1", "Z9")), PACKET)
    assert g["action_evidence_ids"] == ["A1"]


def test_schema_rejects_unknown_action():
    with pytest.raises(ValueError):
        summary(("x", ["F6"]), action="block_user")


def test_prompts_contain_no_raw_identifiers():
    sample = narrator.cases(limit=5, seed=1)
    alerts = casework.alerts().set_index("login_id")
    for p in sample:
        text = narrator.prompt(p)
        user_id = int(alerts.loc[p["login_id"], "user_id"])
        assert str(user_id) not in text and str(p["login_id"]) not in text
        assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        assert "U-" in text and "IP-" in text


GOOD = ('{"claims": [{"text": "The account has 43 earlier logins.", "evidence_ids": ["F6"]}], '
        '"recommended_action": "contact_user_out_of_band", "action_evidence_ids": ["A1"], "confidence": "medium"}')


def test_narrate_with_fake_backend(monkeypatch):
    monkeypatch.setitem(narrator.CALLS, "gemini", lambda c, t, m, e: {"model": m, "status": "completed", "raw": GOOD,
                                                                      "cost_usd": 0.0})
    r = narrator.narrate(None, PACKET, "gemini")
    assert r["model"] == "gemini-3.6-flash" and len(r["grounded"]["claims"]) == 1 and "error" not in r


def test_retries_on_rate_limit(monkeypatch):
    class RateLimited(Exception):
        status_code = 429
    calls = []
    monkeypatch.setattr(narrator.time, "sleep", lambda s: calls.append(s))
    attempts = iter([RateLimited(), RateLimited(), "ok"])

    def fn():
        x = next(attempts)
        if isinstance(x, Exception):
            raise x
        return x
    assert narrator._with_retries(fn) == "ok" and calls == [15.0, 30.0]


def test_no_retry_on_bad_request(monkeypatch):
    class Bad(Exception):
        status_code = 400
    monkeypatch.setattr(narrator.time, "sleep", lambda s: None)
    with pytest.raises(Bad):
        narrator._with_retries(lambda: (_ for _ in ()).throw(Bad()))


def test_gemini_request_shape():
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from google import genai
    bodies = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            bodies.append(json.loads(self.rfile.read(int(self.headers["content-length"]))))
            self.send_response(400)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": {"code": 400, "message": "test", "status": "INVALID_ARGUMENT"}}')

        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = genai.Client(api_key="dummy", http_options={"base_url": f"http://127.0.0.1:{server.server_port}"})
    with pytest.raises(Exception):
        narrator._call_gemini(client, narrator.prompt(PACKET), "gemini-3.8-flash", "low")
    server.shutdown()
    body = bodies[0]
    assert body["store"] is False and body["system_instruction"] == narrator.SYSTEM
    assert body["response_format"]["mime_type"] == "application/json"
    assert "additionalProperties" not in json.dumps(body["response_format"]["schema"])
    assert body["response_format"]["schema"]["properties"]["recommended_action"]["enum"] == list(narrator.ACTIONS)
    assert "IP-abcdef0123" in body["input"] and body["generation_config"]["thinking_level"] == "low"


def test_hard_deadline_stops_a_hung_call():
    import time as _t
    with pytest.raises(narrator.DeadlineTimeout):
        narrator._deadline(lambda: _t.sleep(5), 0.2)
    assert narrator._deadline(lambda: 7, 1) == 7
    assert narrator._retryable(narrator.DeadlineTimeout())
