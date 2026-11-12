# SHAP reason codes (ATO policy, validation)

Code: `deriddled/explain.py`. TreeSHAP contributions from XGBoost (`pred_contribs=True`) for the reputation model, in log-odds. Features are summed into 17 reason groups; a login's reasons are its top 3 groups with a positive contribution, filled into plain-English templates with the login's values. Figure: `docs/figures/shap_global_ato.png`.

## Coverage

| | Value |
| --- | --- |
| Validation logins | 2,633,850 |
| Flagged (CHALLENGE / BLOCK) | 1,790 (1,759 / 31) |
| ATOs flagged | 29 of 33 |
| Flagged logins with ≥ 1 reason | **100%** (PRD target) |
| Flagged logins with 3 reasons | 100% |

## Global importance on flagged logins (mean |SHAP|)

| Reason group | Mean \|SHAP\| | #1 reason (all flagged) | #1 reason (ATOs) |
| --- | --- | --- | --- |
| Unusual for user (likelihood score) | 1.54 | 46.5% | 62.1% |
| Rare network | 1.19 | 11.1% | 0% |
| Country takeover history | 1.10 | 19.3% | 27.6% |
| Network takeover history | 0.99 | 10.3% | 10.3% |
| Rare browser | 0.90 | 10.8% | 0% |
| Rare country | 0.83 | 0.4% | 0% |
| Device type | 0.69 | — | — |
| Network attack history | 0.62 | 1.5% | 0% |
| Time since last login | 0.45 | 0.1% | 0% |
| Time of day | 0.29 | — | — |
| IP activity | 0.28 | — | — |
| Account history | 0.18 | — | — |
| Recent activity | 0.14 | — | — |
| New country | 0.06 | — | — |
| New network | 0.03 | — | — |
| New device | 0.01 | — | — |

## Example reasons

Caught ATO (BLOCK, p = 0.93):
1. New country, network and device for this user (likelihood score 5.7)
2. RO had 48 confirmed takeovers before
3. Rare browser/OS: 0.02% of logins so far

False-alarm CHALLENGE (Indonesia, p = 0.002):
1. Country, network and browser are rarely used by this user (likelihood score 12.5)
2. Network has attack history (77% of its earlier logins from attack IPs)
3. Rare country (ID): 1.2% of logins so far

## Takeaways

- **SHAP explains the model, not the world.** `new_country` scores 0.06 although it's the strongest single signal in the data (105× lift): its information is carried by `lr_score`, which gets the credit. Correlated features share or take each other's credit.
- **Country reputation partly re-introduces identity:** "RO had N confirmed takeovers" is the #1 reason for 28% of caught ATOs, and the false-alarm BLOCKs shown are Romanian logins. To measure in error analysis: challenge / block rates for legitimate Romanian users.
- **Several false-alarm BLOCKs look identical to caught ATOs** (Romania; new country, network and device). They may be unlabelled takeovers; to test in error analysis by checking for the campaign's browser fingerprint.
