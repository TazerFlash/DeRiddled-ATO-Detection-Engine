# De-Riddled: 3-minute walkthrough

A spoken script of about 500 words, roughly 3 minutes at a brisk interview pace (150–160 words per minute). Numbers are validation results; say so if asked. Live demo: https://tazerflash-deriddled.streamlit.app/

---

**[0:00] The problem.**
"Account takeover means someone logs in with your real password, bought from a breach or phished. Banks usually defend with a rule: challenge after five failed attempts. I took a public dataset of 31 million logins and asked whether a learned, explainable risk score could do better on two things at once: catch more takeovers, and bother fewer real users."

**[0:20] Why the rule fails.**
"The first finding was that the rule catches nothing. Twenty-nine of the 33 validation takeovers had zero failed attempts, because the attacker already has the password. The rule only challenges people who mistype. Once you count the friction, it costs more than doing nothing."

**[0:40] Building it honestly.**
"Every feature uses only data from before that login, and a test recomputes rows from raw history to prove there's no leakage. Reputation features only count takeovers confirmed a week earlier, because real labels arrive late. I split by time, and kept the last two months untouched for a final test. One campaign was over half of all takeovers, so I always report it separately."

**[1:00] What works.**
"An ablation showed where the signal is: population frequencies and network reputation, not the anomaly detector or the graph features. I set thresholds from a cost model, not by hand: a missed takeover costs 500, a one-time code costs 0.5."

**[1:15] The experiment.**
"Then I ran shadow mode: the rule and the model decide every one of 2.6 million validation logins. The model stopped 28 of 33 takeovers while challenging 0.05% of users, six times fewer than the rule. Against the strongest simple baseline at exactly the same challenge budget, it stopped 39 points more, with a day-level bootstrap interval of 18 to 59 and an exact McNemar p-value of 0.001."

**[1:45] The red team.**
"The most interesting result came from attacking it. I had an LLM write attack campaigns and ran them through the real scorer, and the model stopped only 2 of 300. 'New country for this account' counted the attacker's own failed guesses, so failing once made them look familiar. Real takeovers almost never fail first, so the data couldn't show it. Measuring novelty against successful logins only raised that to 78 of 300, at a cost of three historical takeovers, which I accepted."

**[2:20] The system around it.**
"It serves from FastAPI at 349 logins per second, 2.3 milliseconds at p95, with online decisions identical to offline. The analyst dashboard exposed a model that punished feedback, which monotone constraints fixed. And a GenAI layer explains alerts and answers analysts' questions in SQL, but never makes the decision."

**[2:45] Close.**
"So the result is: much better than the rule, clearly better than the best simple baseline, robust to an attack the data couldn't show, explainable, and fast enough to serve, with the honest caveat that it rests on 33 takeovers until the test window confirms it."

---

## STAR version (for "tell me about a project")

- **Situation:** Banks challenge logins with static rules that miss takeovers using correct, stolen passwords.
- **Task:** Build a real-time risk score that stops more takeovers without challenging more than 1% of real users, and prove it fairly.
- **Action:**
  - point-in-time features with a leakage test, and delayed labels;
  - calibrated XGBoost with cost-model thresholds and monotone reputation;
  - shadow mode against the rule and a matched-budget baseline, with McNemar, block bootstrap and power;
  - an LLM red team, which found a blind spot that I then fixed;
  - a FastAPI service with parity tests, an analyst dashboard and a GenAI layer kept out of the decision.
- **Result:**
  - 28 / 33 takeovers stopped at 0.05% friction, against 0 / 33 for the rule;
  - +39 points over the best baseline (CI 18–59);
  - synthetic attacks stopped went from 2 to 78 of 300 after the fix;
  - 349 logins/s at p95 2.3 ms.

---

## Likely follow-up questions

**What would you do differently?**
- Red-team the features before trusting validation numbers: historical data only contains the attacks that already happened.
- Constrain the risk features to be monotone from the start.
- Make data order deterministic on day one.
- Build the analyst dashboard much earlier: it found the second most important defect of the project.

**Why did you accept a model that stops fewer real takeovers?**
- The old one stopped 31 of 33 historical takeovers but only 2 of 300 attacks that fail once first. Any attacker could learn that.
- The new one stops 28 of 33, about one takeover fewer on average over three seeds, at the same friction.
- Robustness to an obvious evasion is worth one historical takeover, and the trade-off is documented.

**Precision is only 2%. Isn't that bad?**
- Takeovers are 1 in 80,000 logins, so 2% is about 1,600× the base rate.
- The cost model chooses cheap one-time codes for anything above p = 0.00111, so friction stays at 0.05% of real users.
- The BLOCK tier is 37.5% precise, and 29 of its 32 blocks are takeovers or known attack IPs.
- PR-AUC is 0.34, against 0.009 for the best non-ML baseline.

**Why not optimise AUC?**
- AUC averages over every threshold, but the bank operates at one: a challenge budget well under 1%.
- I report recall at a fixed challenge rate and cost per 1,000 logins.
- With 33 positives, AUC differences are mostly noise.

**How do you know it isn't just learning the Romanian campaign?**
- Every result is split into campaign and non-campaign: 9 of 14 non-campaign takeovers stopped.
- I removed the country features after finding they over-challenged genuine Romanian users at 131× the average rate.

**33 positives is tiny. How confident are you?**
- Confident about "much better than the rule": the rule stopped none, and 8 takeovers give 80% power.
- Less sure about the exact gain over the baseline: the interval is 18 to 59 points, and it's a validation number.
- The test window is the confirmation, with its sample size fixed in advance.

**Why McNemar and not a two-proportion test?**
- Both systems saw the same takeovers, so the data is paired.
- Only the disagreements carry information, and McNemar is an exact coin-flip test on them.

**Why bootstrap by day?**
- Takeovers arrive in campaign bursts, so logins on the same day are correlated.
- Resampling single logins would give intervals that are too narrow.

**Why is the LLM kept out of the decision?**
- The decision has to be calibrated, fast (milliseconds) and auditable. An LLM is none of these reliably.
- The LLM explains alerts with cited evidence, answers analysts' questions in guarded SQL, and writes red-team campaigns. Code checks its claims, and I evaluate it like a model: fixed eval sets, held-out sets after tuning, blind A/B comparisons.

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
