# Case narrator: cited AI summaries for analysts

Code: `deriddled/narrator.py` (`python -m deriddled.narrator show | estimate | run --provider claude --model claude-haiku-5-5 --limit N`), `deriddled/privacy.py`, `deriddled/label_sheet.py`. Tests: `tests/test_narrator.py`. In the dashboard: the **AI case summary** panel in each alert.

## What it does

For each alert, the narrator turns the evidence into 4–6 short claims that each cite the evidence they rest on, plus a suggested next step for the analyst. The model's ALLOW / CHALLENGE / BLOCK decision is never changed by it.

## The evidence packet

Each alert becomes a list of numbered evidence items. Nothing else is sent to the model.

| IDs | Content |
| --- | --- |
| A1 | Model decision, calibrated probability to 6 decimals, its band ("at or above the CHALLENGE threshold and below the BLOCK threshold"), the thresholds, the hashed account |
| R1–R3 | The model's top three reasons (TreeSHAP) |
| F1–F20 | Features in plain words: whether the country, network, IP range, IP and device were seen before; account history counts; failed logins in the last hour and 24 hours; the likelihood score, with what its sign means; network shares and attack rates; takeover history of the network, range and IP; IP activity |
| H1 | How much of the account's history is listed ("all 3 earlier logins", or "only the 10 most recent of 42") |
| L0–L10 | This login and up to 10 earlier ones: time, place, network, hashed IP, browser and device, and whether the password was correct |

**Privacy:** account IDs, IPs and /24 ranges are salted SHA-256 hashes (`U-…`, `IP-…`, `NET-…`), with the salt kept in `.env`. A test checks that no raw ID or IPv4 address appears in any prompt.

## Output and grounding

- **Structured output:** a JSON schema (claims with `evidence_ids`, `recommended_action`, `action_evidence_ids`, `confidence`), validated with Pydantic.
- **Grounding check, in code:** a claim is removed if it cites no valid evidence ID, or if any number in it doesn't appear in the evidence it cites (1% tolerance; version strings must match exactly). Removed claims are shown separately in the dashboard.
- **Suggested actions:** `confirm_takeover`, `contact_user_out_of_band`, `likely_false_alarm` or `needs_more_information`. A decision guide in the prompt says a wrong password can never mean `confirm_takeover`.

## Models and cost

- **Claude Haiku 5.5:** about $0.001 per alert (about $1 per 1,000 alerts), median about 6 s.
- **Gemini 3.6 Flash** on the free tier is an optional backend (`--provider gemini`), limited to 20 requests per day.

Retries cover 429 and 5xx errors with backoff, and every call has a hard deadline.

## How faithfulness was measured

The code check catches wrong IDs and numbers, but not wrong meaning, so claims were labelled:
- **supported:** every fact is in the cited evidence;
- **partly:** the main fact is supported, but a detail is not, such as an unstated "because", a generalisation or a site-wide share described as the account's;
- **unsupported:** says something the cited evidence does not say, or the opposite.

**Strict faithfulness** counts only supported claims; **lenient** counts supported and partly. Intervals use a case bootstrap, because claims within a case are not independent.

The labels so far come from **AI judges** (Claude Opus subagents), not people. Prompt versions were compared on the same alerts, shuffled under random IDs so the judges could not tell which version wrote what, with a paired case bootstrap.

| Prompt | Alerts | Strict | Lenient | Unsupported | Recommendations reasonable |
| --- | --- | --- | --- | --- | --- |
| v2 | 100 (champion D's alerts) | 87.8% | 99.8% | 1 | 81 / 100 |
| v3 | 100 (dev) | 79.1% | 95.6% | 26 | 75 / 100 |
| v4 | 100 (dev) | 88.8% | 98.1% | 11 | 85 / 100 |
| v4 | 56 (held out) | 91.2% | 98.4% | 5 | 47 / 56 |
| **v5 (live)** | **56 (held out)** | **93.4%** | **100%** | **0** | **48 / 56** |

The v2 row used an earlier, looser rubric, so compare it only roughly with the others.

- **v3 → v4:** +9.6 points strict (paired 95% CI 6.3–12.8). v4 added the H1 history item, site-wide wording for network shares, the sign of the likelihood score, a no-ranking rule and the decision guide. Before it, the recommendation was the same action in 94 of 100 cases.
- **v4 → v5:** removed every unsupported claim. Most of them came from misreading a double-negative flag ("no earlier successful login…: no"). The strict gain (+2.2 points, CI −1.7 to +6.1) is within noise. Scored on the 56 alerts no prompt had been tuned on.

**Still to do:** a human spot-check of the judge. `eval/narrator_spotcheck.xlsx` holds 40 blind claims; label them, then run `python -m deriddled.label_sheet agree` for agreement and Cohen's kappa.
