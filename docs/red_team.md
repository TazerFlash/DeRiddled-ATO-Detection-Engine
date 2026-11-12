# Red team: LLM-written attacks against the live scorer

Code: `deriddled/redteam.py` (`python -m deriddled.redteam write | show | run --seed N --policies …`). Scenarios: `eval/redteam_scenarios.json`. Results: `data/ops/redteam/recall_valid_seed{0,1}.csv`. Tests: `tests/test_redteam.py`.

## Why

Validation measures the model against the attacks that already happened. The 33 validation takeovers almost all come from one campaign and almost never fail a password first, so a model can score well on them and still be easy to evade. A red team asks what a thinking attacker would try next.

## How it works

1. **The LLM writes parameters, not logins.** Claude Sonnet 5.5 proposed five campaigns as structured settings (JSON schema, validated with Pydantic):
   - origin: the victim's country or abroad;
   - network: the victim's own ISP, a common local ISP, a rare network, or an attack-listed one;
   - device: the victim's own, a common one, or a fixed attacker device;
   - failed attempts before success;
   - timing;
   - whether the IPs are on the threat list.

   The writer cost $0.02.
2. **A deterministic generator builds the logins.** For each campaign it picks 30 real victim accounts per day (at least 5 successful logins in the last 30 days, no takeover history) and copies their usual country, network or device where the scenario says so. It then emits the failed attempts and the final successful login. Every query is ordered and samples are hash-ordered, so the same seed gives identical attacks.
3. **Injection into real traffic.** The synthetic logins are mixed into two real validation days (10 and 13 Sep 2020, about 84,000 real account logins). They are scored by the same online code the API runs (`parity.warm_start` and the streaming state), not by an offline shortcut.
4. **Recall per scenario.** A takeover counts as stopped if its successful login is challenged or blocked, with a Wilson 95% interval per scenario.

## The five campaigns

| Campaign | Origin | Network | Device | Fails first | On threat list |
| --- | --- | --- | --- | --- | --- |
| Noisy credential stuffing | abroad | attack-listed | fixed | 6 | yes |
| Same network, same device, low and slow | victim's country | victim's ISP | copies victim | 1 | no |
| Residential proxy blend-in | victim's country | common local ISP | common | 2 | no |
| Rented servers at night | abroad | rare network | fixed | 3 | no |
| Careful foreign mobile mimic | abroad | common local ISP | common | 1 | no |

## The finding

Takeovers stopped out of 60 per campaign (seed 0 / seed 1):

| Campaign | D `ato_xgb_mono` | **E `ato_xgb_ok`** |
| --- | --- | --- |
| Noisy credential stuffing | 0 / 3 | **35 / 51** |
| Same network, same device | 0 / 0 | 0 / 0 |
| Residential proxy blend-in | 0 / 0 | 0 / 0 |
| Rented servers at night | 2 / 9 | **43 / 47** |
| Careful foreign mobile mimic | 0 / 0 | 0 / 2 |
| **Total of 300** | **2 / 12** | **78 / 100** |
| Real alerts in the same two days | 57 | 52–53 |

Champion D stopped 31 of 33 real takeovers but only 2–12 of 300 synthetic ones. On the noisy campaign it flagged 48–67% of the **failed** attempts, then let the successful login through.

**The cause:** the novelty features ("new country / network / device for this account") and the likelihood score counted *every* earlier login, including failed ones. By the time the attacker's password worked, their own failed guesses had made their country, network and device look familiar. The real takeovers almost never fail first, so historical data could not show this.

## The fix: novelty against successful logins only

- **New features:** `sql/novelty_ok.sql` and `deriddled/novelty_ok.py` count only earlier **successful** logins per account and per country, network, IP, /24 range, device and browser. They give five `new_*_ok` flags and `lr_score_ok`.
- **Online:** `deriddled/state.py` keeps the same success-only counters.
- **Parity:** the online features match the offline ones exactly (0 mismatches on 15,689 logins in a busy 6-hour window).
- **Tests:** `tests/test_redteam.py` checks that failed attempts don't count as familiar and that a success does.

**The trade-off.** On the real validation takeovers E stops 28 instead of 31 (mean over three seeds 28.7 vs 30.3), at the same friction, and expected cost rises from 1.16 to 1.66 per 1,000 logins. E was adopted (MLflow `deriddled-ato` v4, champion), because a model any attacker can beat by failing once is not robust.

## What is still undetectable

Two campaigns stay at 0 for both models: an attacker who uses the victim's country, the victim's own ISP or a common local one, and the victim's device or a common one. From login metadata alone that attacker looks like the account owner. Catching them needs other signals: MFA outcomes, device binding, session behaviour or behavioural biometrics.

## Limits

- The scenarios are an LLM's guess at attacker behaviour, not observed attacks. They test robustness, not real-world recall.
- Two seeds and two days. The per-scenario intervals are wide (for example 0.46–0.70 for 35 of 60).
- E was chosen after seeing these results, so the red-team numbers for E are not independent. A fresh set of campaigns would be the honest re-test.
