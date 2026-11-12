# De-Riddled: 3-minute walkthrough

A spoken script of about 450 words, roughly 3 minutes at a brisk interview pace (150–160 words per minute). Numbers are validation results; say so if asked.

---

**[0:00] The problem.**
"Account takeover means someone logs in with your real password, bought from a breach. Banks usually defend with a rule: challenge after five failed attempts. I took a public dataset of 31 million logins and asked whether a learned, explainable risk score could do better on two things at once: catch more takeovers, and bother fewer real users."

**[0:20] Why the rule fails.**
"The first finding was that the rule catches nothing. Twenty-nine of the 33 validation takeovers had zero failed attempts, because the attacker already has the password. The rule only challenges people who mistype. Once you count the friction, it costs more than doing nothing."

**[0:40] Building it honestly.**
"Every feature uses only data from before that login, and a test recomputes rows from raw history to prove there's no leakage. Reputation features only count takeovers confirmed a week earlier, because real labels arrive late. I split by time, and kept the last two months untouched for a final test. One campaign was 56% of all takeovers, so I always report it separately."

**[1:05] What works.**
"An ablation showed where the signal is: population frequencies and network reputation, not the anomaly detector or the graph features. I set thresholds from a cost model, not by hand: a missed takeover costs 500, a one-time code costs 0.5. That threshold lands within two hundredths of the cost curve's minimum."

**[1:30] The experiment.**
"Then I ran shadow mode: the rule and the model decide every one of 2.6 million validation logins. The model stopped 31 of 33 takeovers while challenging 0.05% of users, six times fewer than the rule. Against the strongest simple baseline at exactly the same challenge budget, it stopped 48 points more, with a day-level bootstrap interval of 30 to 66 and an exact McNemar p-value of 3 in 100,000. A power calculation told me the final test window is enough against the rule but only borderline against the baseline, because of the winner's curse."

**[2:10] What the system taught me.**
"I served it with FastAPI at 413 logins per second, p95 3 milliseconds, with a parity test proving online features identical to training. Then I built the analyst dashboard, and simulating analyst feedback showed that confirming fraud on a network *lowered* other scores. The model had learned that networks with lots of takeover history are big, mostly safe ISPs. Monotone constraints fixed it and improved the model on every seed. Chasing that, I also found that training wasn't reproducible, because DuckDB's parallel scan changed row order."

**[2:45] Close.**
"So the result is: much better than the rule, clearly better than the best simple baseline, explainable, and fast enough to serve, with the honest caveat that it rests on 33 takeovers until the test window confirms it."

---

## STAR version (for "tell me about a project")

- **Situation:** Banks challenge logins with static rules that miss takeovers using correct, stolen passwords.
- **Task:** Build a real-time risk score that stops more takeovers without challenging more than 1% of real users, and prove it fairly.
- **Action:**
  - point-in-time features with a leakage test, and delayed labels;
  - calibrated XGBoost with cost-model thresholds;
  - shadow mode against the rule and a matched-budget baseline, with McNemar, block bootstrap and power;
  - a FastAPI service with parity tests, and an analyst dashboard.
- **Result:** 31 / 33 takeovers stopped at 0.05% friction vs 0 / 33 for the rule; +48 pts over the best baseline (CI 30–66); 413 logins/s at p95 3 ms. Building the dashboard exposed and fixed a backwards model response.

---

## Likely follow-up questions

**What would you do differently?**
- Constrain the risk features to be monotone from the start.
- Make data order deterministic on day one.
- Build the analyst dashboard much earlier: it found the most important defect of the project.

**Why not optimise AUC?**
- AUC averages over every threshold, but the bank operates at one: a challenge budget well under 1%.
- I report recall at a fixed challenge rate and cost per 1,000 logins.
- With 33 positives, AUC differences are mostly noise.

**How do you know it isn't just learning the Romanian campaign?**
- Every result is split into campaign and non-campaign: 12 of 14 non-campaign takeovers stopped.
- I removed the country features after finding they over-challenged genuine Romanian users.

**33 positives is tiny. How confident are you?**
- Confident about "much better than the rule": the rule stopped none, and 7 takeovers give 80% power.
- Less sure about the exact gain over the baseline: the interval is 30 to 66 points, and it's a validation number.
- The test window is the confirmation, with its sample size fixed in advance.

**Why McNemar and not a two-proportion test?**
- Both systems saw the same takeovers, so the data is paired.
- Only the disagreements carry information, and McNemar is an exact coin-flip test on them.

**Why bootstrap by day?**
- Takeovers arrive in campaign bursts, so logins on the same day are correlated.
- Resampling single logins would give intervals that are too narrow.

**What happens if the scorer is slow or down?**
- It fails open: after 200 ms the login is allowed and logged.
- Locking every user out during an outage is worse than missing an attack for a few seconds.

**How would you keep it working over time?**
- Monitor score PSI and the weekly challenge rate, alerting on the model's output rather than on noisy features.
- Analyst labels feed reputation immediately and retraining monthly.
- A challenger replaces the champion only if it wins on the newest month; rollback means moving the registry alias.

**Is unlabelled data legitimate?**
- No. Most of the model's false BLOCKs carried the attack campaign's exact fingerprint, so they're probably unlabelled attacks.
- With production data I'd review a sample of alerts to estimate the true label rate.
