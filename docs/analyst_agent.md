# "Ask the Watchtower": the SQL analyst agent

Code: `deriddled/analyst_db.py` (builds the database), `deriddled/analyst.py` (the agent; `python -m deriddled.analyst "question"`), `deriddled/analyst_eval.py` (the eval; `--set dev | holdout`). Question sets: `eval/analyst_questions.yaml` (30 dev), `eval/analyst_holdout.yaml` (10 held out). Tests: `tests/test_analyst.py` (17 tests, no API calls). In the dashboard: the **Ask the data** page.

## What it does

An analyst types a question such as "Which networks had more than 3 account takeovers?". Claude Haiku 5.5 explores the data with SQL, then declares its answer: the final SQL, its result table and a one-paragraph answer. The dashboard shows every tool call it made.

## Defence in depth

The agent writes its own SQL, so it is treated as untrusted.

| Layer | Guard |
| --- | --- |
| Data | A separate DuckDB file (`data/analyst/analyst.duckdb`) holding only hashed identifiers: 16.1M logins (1 Feb – 14 Sep 2020) with `user_hash`, `ip_hash`, `subnet_hash`, plus the 503,676-decision log. No raw ID or IP is in the file. |
| Connection | Opened read-only, with `enable_external_access = false` (no file or network reads) and `lock_configuration = true` |
| Statement | Exactly one statement, and it must parse as a `SELECT`. Anything else is rejected before it runs. |
| Size | Every query is wrapped in a forced `LIMIT`. At most 200 rows come back and 50 are shown to the model. |
| Time | A 30 s timer calls `interrupt()` on the connection |
| Loop | At most 8 model turns per question; `user_history` accepts only a well-formed `U-` hash and at most 50 rows |

Tests cover writes, `ATTACH`, file reads, multiple statements, the row cap, the timeout, raw identifiers and injection through the history tool.

## Tools

- `run_sql(sql)`: explore.
- `user_history(user_hash, limit)`: recent logins for one hashed account.
- `final_answer(sql, answer)`: declare the answer. The loop stops on the first successful call, and that query's result is what gets scored.

## How it is scored: execution accuracy

The scorer compares **result tables, not SQL text**, because there are many correct ways to write a query:
- column names and row order don't matter, and extra columns are allowed;
- each gold column must match a predicted column, compared as a multiset, and rows are then matched greedily;
- numbers must agree within the question's stated tolerance; midnight timestamps compare as dates.

Questions with ties in a top-N answer were replaced with threshold questions, so there is only one correct answer.

## Results

| Run | Set | Correct | Notes |
| --- | --- | --- | --- |
| v1 | dev (30) | 27 / 30 (Wilson CI 74–97%) | It returned rankings where one row was asked for, and its last check query was scored instead of its answer |
| v3, with `final_answer` | dev (30) | 30 / 30 | 10/10 easy, 12/12 medium, 8/8 hard |
| v3 | held out (10) | 10 / 10 | Before the champion change |
| v3 | held out (10) | 9 / 10 | After the decision log was rebuilt for champion E |

The one held-out miss (x06): the agent excluded the 5 non-account IDs, giving 31 where the gold answer is 36. That is a defensible reading, but the gold answer was not changed after the fact.

**Cost:** about $0.77 per 1,000 questions on Haiku 5.5; median 3.5 s per question.

Because v3 was tuned on the dev set, 30 / 30 there is optimistic. The held-out 9–10 / 10 is the honest number.

## In the public demo

The hosted dashboard shows saved answers for 10 example questions, at no cost. Visitors can ask 3 questions of their own per visit (100 per day in total, at most 300 characters each) when a spend-capped API key is configured.
