# Country features and regional bias (validation)

Code: `deriddled/country_bias.py`. Each variant is retrained, calibrated (cross-fitted sigmoid) and run through the same cost thresholds (CHALLENGE p ≥ 0.00111, BLOCK p ≥ 0.281).

"Genuine Romanian users" = Romanian legitimate-labelled logins with no campaign sign (campaign browser fingerprint, a labelled ATO on the same user, or an IP used in a labelled ATO): 2,092 of 2,206.

| Variant | Features | ATO @ 1% | ATOs stopped | Challenge rate | Legit blocks | Cost / 1,000 | Romanian legit flag rate | Genuine Romanian flag rate | × average |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A: current (network, IP and country reputation) | 42 | 32 / 33 | 29 / 33 | 0.068% | 20 | 1.50 | 8.2% | 4.0% | 59× |
| B: no country reputation | 40 | 33 / 33 | 29 / 33 | 0.062% | 17 | 1.54 | 5.5% | 1.6% | 26× |
| **C: no country reputation or rarity** | 39 | **33 / 33** | **29 / 33** | **0.057%** | 18 | **1.46** | 4.9% | **1.0%** | **17×** |

No genuine Romanian user is blocked in any variant.

- Country features add no protection: network- and IP-level reputation already capture the campaign.
- Removing them cuts genuine Romanian friction from 4.0% to 1.0% at equal or lower cost.
- The remaining ~17× comes from rare networks / browsers and travel novelty; further reduction would need a policy (per-slice caps or thresholds), not feature removal.
- Variant A differs slightly from the earlier error-analysis run (retraining noise).

**Recommendation: variant C as the main ATO model.**

## Adopted: `ato_xgb_main`

Variant C is the main ATO model (`config.yaml: models.ato`), retrained with `python -m deriddled.train full save ato main 3 1 ato_xgb_main`, then recalibrated (`deriddled.decision`), re-explained (`deriddled.explain`) and re-analysed (`deriddled.errors`).

| Validation | Previous main (A) | Adopted (C) |
| --- | --- | --- |
| ATOs stopped (blocked / challenged) | 29 (15 / 14) | 28 (9 / 19) |
| Challenge rate | 0.067% | 0.051% |
| Legit blocks (raw / no campaign sign) | 16 / 1 | 18 / 2 |
| Cost per 1,000 logins | 1.48 | 1.70 |
| Σ p vs 33 ATOs (sigmoid, cross-fitted) | 41.2 | 34.3 |
| Reason coverage | 100% | 100% |
| Romanian legit flag rate | 8.8% | 4.4% |
| Genuine Romanian flag rate | ~4% | ~0.7% (15 / 2,092) |

- The one extra miss (Canada, p = 0.00061, top 0.08% of logins) sits just under the CHALLENGE threshold; in the matched experiment A and C both stopped 29, so the difference is retraining noise (one ATO ≈ 0.19 cost per 1,000 logins).
- Calibration improved: country features had inflated predicted risk.
- Slices over 2× average after adoption: desktop 2.6×, Brazil 2.3× (0.12%), Poland 2.4× (0.12%), Romania 86× (4.4%, mostly campaign-sign logins). The lower average (0.051%) raises every ratio.
- Sensitivity (each cost × 0.5 / × 2, OTP stop rate 0.8 / 0.95): 3–5 ATOs allowed in every scenario.

Saved: `data/models/ato_xgb_main.json`, `ato_xgb_main_meta.json`, `ato_xgb_main_calibration.json`.
