# Reputation label delay (validation)

Code: `deriddled/delay_test.py`; reputation builds via `python -m deriddled.reputation full <days>` (folders `data/features/reputation_d{days}`; 7 days is the default `data/features/reputation`). For each delay the main ATO model (39 features) is retrained, calibrated (cross-fitted sigmoid) and run through the cost thresholds.

| Label delay | ATOs stopped (policy) | Recall @ 1% | Campaign @ 1% | Other @ 1% | Challenge rate | Cost / 1,000 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 day | 29 / 33 | 33 / 33 | 19 / 19 | 14 / 14 | 0.053% | 1.54 |
| **7 days (adopted)** | 28 / 33 | 33 / 33 | 19 / 19 | 14 / 14 | 0.053% | 1.72 |
| 14 days | 28 / 33 | 33 / 33 | 19 / 19 | 14 / 14 | 0.059% | 1.68 |
| 30 days | 27 / 33 | 32 / 33 | 19 / 19 | 13 / 14 | 0.054% | 1.85 |

- Results don't depend on the 7-day assumption: 1 → 30 days costs ~2 ATOs under the policy and 1 at 1%, each step about the size of retraining noise.
- Reputation mostly captures long-lived network risk: the campaign used the same networks for 10 months, so older confirmed takeovers keep those networks flagged even with a month's delay.
- Limitation: a brand-new campaign on fresh networks gets no reputation signal until its first takeovers are confirmed; behaviour and network-rarity features (30 / 33 without reputation in the ablation) are the safety net.
- Build times: 18–22 min per delay on the full data.
