"""Error analysis on validation: missed ATOs, false alarms vs unlabelled-takeover signs, slice challenge rates, missed attack-IP logins."""
import json

import numpy as np
import pandas as pd
import xgboost as xgb

from deriddled.config import connect, load_config, path
from deriddled.evaluate import top_rate_flags
from deriddled.explain import grouped_shap, load_policy, score
from deriddled.train import load, matrix

CAMPAIGN_BROWSER, CAMPAIGN_OS = "Chrome 79.0.3945.192.218", "Mac OS X 10.14.6"
SHOW = ["login_id", "country", "device_type", "p", "user_prior_logins", "new_country", "new_asn", "new_device",
        "asn_freq", "asn_attack_rate", "asn_ato_prior", "country_ato_prior", "lr_score"]


def raw_columns(login_ids) -> pd.DataFrame:
    src = path(load_config()["data"]["logins_dir"]).as_posix()
    con = connect()
    con.register("ids", pd.DataFrame({"login_id": list(login_ids)}))
    return con.execute(f"""SELECT login_id, ip, browser, os FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true)
                           JOIN ids USING (login_id)""").df()


def ato_context() -> tuple[set, set]:
    src = path(load_config()["data"]["logins_dir"]).as_posix()
    ato = connect().execute(f"SELECT user_id, ip FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true) WHERE is_ato").df()
    return set(ato.user_id), set(ato.ip)


def missed_atos(df: pd.DataFrame, booster, meta) -> None:
    miss = df[df.is_ato & (df.action == "ALLOW")].copy()
    rank = df["margin"].rank(ascending=False, pct=True)
    miss["rank_pct"] = rank.loc[miss.index] * 100
    print(f"== missed ATOs: {len(miss)}")
    print(miss[SHOW + ["rank_pct"]].round(6).to_string(index=False))
    shap = grouped_shap(miss, booster, meta)
    for idx in miss.index:
        s = shap.loc[idx].sort_values()
        print(f"  login {miss.at[idx, 'login_id']}: lowered by {', '.join(f'{g} {v:+.2f}' for g, v in s.head(3).items())}; "
              f"raised by {', '.join(f'{g} {v:+.2f}' for g, v in s.tail(3)[::-1].items())}")
    print()


def false_alarms(df: pd.DataFrame) -> None:
    ato_users, ato_ips = ato_context()
    legit = df[~df.is_ato]
    flagged = legit[legit.action != "ALLOW"].copy()
    raw = raw_columns(flagged.login_id).set_index("login_id")
    flagged = flagged.join(raw, on="login_id")
    flagged["campaign_fingerprint"] = (flagged.browser == CAMPAIGN_BROWSER) & (flagged.os == CAMPAIGN_OS)
    flagged["user_has_labelled_ato"] = flagged.user_id.isin(ato_users)
    flagged["ip_used_in_ato"] = flagged.ip.isin(ato_ips)
    flagged["any_sign"] = flagged[["campaign_fingerprint", "user_has_labelled_ato", "ip_used_in_ato"]].any(axis=1)

    src = path(load_config()["data"]["logins_dir"]).as_posix()
    base = connect().execute(f"""
        SELECT AVG((browser = '{CAMPAIGN_BROWSER}' AND os = '{CAMPAIGN_OS}')::INT) FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true)
        WHERE NOT is_ato AND NOT is_non_account AND ts >= TIMESTAMP '2020-08-01' AND ts < TIMESTAMP '2020-10-01'""").fetchone()[0]

    print(f"== false alarms: {len(flagged):,} legitimate logins flagged "
          f"(BLOCK {int((flagged.action == 'BLOCK').sum())}, CHALLENGE {int((flagged.action == 'CHALLENGE').sum())})")
    print(f"campaign fingerprint among ALL legit validation logins: {base:.5%}")
    summary = flagged.groupby("action")[["campaign_fingerprint", "user_has_labelled_ato", "ip_used_in_ato", "any_sign"]].agg(["sum", "mean"])
    print(summary.round(4).to_string())
    print("\nfalse alarms by country (top 8):")
    print(flagged.groupby("country").agg(n=("login_id", "size"), blocks=("action", lambda a: (a == "BLOCK").sum()),
                                         campaign_fp=("campaign_fingerprint", "sum"), any_sign=("any_sign", "sum"))
          .sort_values("n", ascending=False).head(8).to_string())
    print("\nfalse-alarm BLOCKs:")
    cols = ["login_id", "country", "p", "browser", "os", "campaign_fingerprint", "user_has_labelled_ato", "ip_used_in_ato"]
    print(flagged[flagged.action == "BLOCK"].sort_values("p", ascending=False)[cols].round(3).to_string(index=False))
    print()


def slices(df: pd.DataFrame) -> None:
    legit = df[~df.is_ato].copy()
    legit["flag"] = legit.action != "ALLOW"
    avg = legit.flag.mean()
    top_countries = legit.country.value_counts().head(5).index.tolist()
    groups = {
        "new user (<3 prior)": legit.user_prior_logins < load_config()["serving"]["new_user_min_logins"],
        "returning user": legit.user_prior_logins >= load_config()["serving"]["new_user_min_logins"],
        "mobile": legit.device_type == "mobile",
        "desktop": legit.device_type == "desktop",
        **{f"country {c}": legit.country == c for c in top_countries + (["RO"] if "RO" not in top_countries else [])},
    }
    rows = [{"slice": name, "legit_logins": int(m.sum()), "challenge_or_block_rate": legit.flag[m].mean(),
             "block_rate": (legit.action[m] == "BLOCK").mean(), "x_average": legit.flag[m].mean() / avg}
            for name, m in groups.items()]
    out = pd.DataFrame(rows)
    out["flag_over_2x"] = out.x_average > 2
    print(f"== slice metrics on legitimate logins (average challenge-or-block rate {avg:.4%})")
    print(out.to_string(index=False, formatters={"challenge_or_block_rate": "{:.4%}".format, "block_rate": "{:.4%}".format,
                                                 "x_average": "{:.1f}".format}))
    print()


def attack_ip_misses() -> None:
    models = path(load_config()["data"]["models_dir"])
    name = load_config()["models"]["attack_ip"]
    meta = json.loads((models / f"{name}_meta.json").read_text())
    model = xgb.XGBClassifier()
    model.load_model(models / f"{name}.json")
    df = load("attack_ip", "valid")
    s = pd.Series(model.predict(matrix(df, meta["features"], meta["categories"]), output_margin=True), index=df.index)
    df["caught"] = top_rate_flags(s, 0.10)
    pos = df[df.is_attack_ip]
    cols = ["new_country", "new_asn", "new_device", "new_ip", "login_successful"]
    meds = ["asn_attack_rate", "asn_freq", "ip_prior_logins", "ip_users_24h", "subnet_users_24h", "user_prior_logins"]
    table = pd.concat([
        pos.groupby("caught")[cols].mean().T.rename(columns={True: "caught", False: "missed"}),
        pos.groupby("caught")[meds].median().T.rename(columns={True: "caught", False: "missed"}),
    ])
    legit = df[~df.is_attack_ip]
    table["legit (all)"] = pd.concat([legit[cols].mean(), legit[meds].median()])
    print(f"== attack IP @ 10%: {int(pos.caught.sum()):,} caught, {int((~pos.caught).sum()):,} missed of {len(pos):,}")
    print("(rows 1-5: share true; rest: medians)")
    print(table.round(4).to_string())
    print("\nmissed attack-IP logins: top countries / ASNs")
    miss = pos[~pos.caught]
    print(pd.concat([miss.country.value_counts(normalize=True).head(5).rename("country share"),
                     pos.groupby("country").caught.mean().rename("caught rate")], axis=1).dropna().head(5).round(3).to_string())
    print(miss.asn.astype(str).value_counts(normalize=True).head(5).round(3).to_string())


def run() -> None:
    booster, meta, cal = load_policy()
    df = score(load("ato", "valid"), booster, meta, cal)
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 30)
    missed_atos(df, booster, meta)
    false_alarms(df)
    slices(df)
    attack_ip_misses()


if __name__ == "__main__":
    run()
