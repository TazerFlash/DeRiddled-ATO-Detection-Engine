"""TreeSHAP reason codes for the ATO policy: grouped plain-English top-3 reasons for every CHALLENGE / BLOCK, plus global importance."""
import json

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import xgboost as xgb

from deriddled.config import ROOT, load_config, path
from deriddled.train import load, matrix

MODEL = load_config()["models"]["ato"]

GROUPS = {
    "new_country": ["new_country", "new_country_ok"],
    "new_network": ["new_asn", "new_subnet24", "new_ip", "new_asn_ok", "new_subnet24_ok", "new_ip_ok"],
    "new_device": ["new_device", "new_device_ok"],
    "rare_network": ["asn_freq", "asn_users_24h"],
    "rare_country": ["country_freq"],
    "rare_browser": ["ua_freq"],
    "network_attack_history": ["asn_attack_rate", "asn_fail_rate", "ip_prior_attack_ip", "ip_prior_fails"],
    "network_takeover_history": ["asn_ato_prior", "asn_ato_rate", "subnet_ato_prior", "subnet_ato_rate",
                                 "ip_ato_prior", "ip_ato_rate"],
    "country_takeover_history": ["country_ato_prior", "country_ato_rate"],
    "unusual_for_user": ["lr_score", "lr_score_ok"],
    "device_type": ["device_type"],
    "account_history": ["user_prior_logins", "user_prior_successes"],
    "time_since_last_login": ["secs_since_prev", "secs_since_prev_success"],
    "recent_activity": ["user_logins_1m", "user_logins_1h", "user_fails_1h", "user_logins_24h", "user_fails_24h",
                        "user_fail_ratio_24h"],
    "ip_activity": ["ip_prior_logins", "ip_logins_24h", "ip_users_24h", "ip_fails_24h", "subnet_logins_24h",
                    "subnet_users_24h"],
    "time_of_day": ["hour", "weekday"],
    "measurement": ["rtt_present"],
}


def _days(secs) -> str:
    return "no earlier login" if pd.isna(secs) else f"{secs / 86400:.0f} days" if secs >= 86400 else f"{secs / 3600:.1f} hours"


def _share(x: float) -> str:
    pct = 100 * x
    return "< 0.0001%" if pct < 1e-4 else f"{pct:.2g}%" if pct < 0.01 else f"{pct:.2f}%"


def _takeovers(n: int) -> str:
    return f"{n} confirmed takeover{'' if n == 1 else 's'}"


def _unusual(r) -> str:
    new = [name for flag, name in (("new_country", "country"), ("new_asn", "network"), ("new_device", "device"))
           if bool(getattr(r, f"{flag}_ok", getattr(r, flag)))]
    listed = new[0] if len(new) == 1 else ", ".join(new[:-1]) + " and " + new[-1] if new else ""
    what = f"New {listed} for this user" if new else "Country, network and browser are rarely used by this user"
    return f"{what} (likelihood score {getattr(r, 'lr_score_ok', r.lr_score):.1f})"


TEMPLATES = {
    "new_country": lambda r: f"No earlier successful login from {r.country} for this user",
    "new_network": lambda r: f"No earlier successful login from this network (ASN {r.asn}) / IP range for this user",
    "new_device": lambda r: f"No earlier successful login with this browser/OS/device ({r.device_type}) for this user",
    "rare_network": lambda r: f"Rare network (ASN {r.asn}): {_share(r.asn_freq)} of logins so far",
    "rare_country": lambda r: f"Rare country ({r.country}): {_share(r.country_freq)} of logins so far",
    "rare_browser": lambda r: f"Rare browser/OS: {_share(r.ua_freq)} of logins so far",
    "network_attack_history": lambda r: f"Network has attack history ({r.asn_attack_rate:.0%} of its earlier logins from attack IPs)",
    "network_takeover_history": lambda r: f"Network / IP range had {_takeovers(int(max(r.asn_ato_prior, r.subnet_ato_prior)))} before",
    "country_takeover_history": lambda r: f"{r.country} had {_takeovers(int(r.country_ato_prior))} before",
    "unusual_for_user": _unusual,
    "device_type": lambda r: f"Device type: {r.device_type}",
    "account_history": lambda r: f"Little account history ({int(r.user_prior_logins)} earlier logins)",
    "time_since_last_login": lambda r: f"Last successful login: {_days(r.secs_since_prev_success)} ago",
    "recent_activity": lambda r: f"Recent activity: {int(r.user_logins_24h)} logins / {int(r.user_fails_24h)} failures in 24 h",
    "ip_activity": lambda r: f"IP activity: {int(r.ip_users_24h)} accounts on this IP in 24 h",
    "time_of_day": lambda r: f"Unusual time: {int(r.hour):02d}:00",
    "measurement": lambda r: "Network latency not measured",
}


def load_policy():
    models = path(load_config()["data"]["models_dir"])
    meta = json.loads((models / f"{MODEL}_meta.json").read_text())
    cal = json.loads((models / f"{MODEL}_calibration.json").read_text())
    booster = xgb.XGBClassifier()
    booster.load_model(models / f"{MODEL}.json")
    return booster, meta, cal


def score(df: pd.DataFrame, booster, meta, cal) -> pd.DataFrame:
    X = matrix(df, meta["features"], meta["categories"])
    df["margin"] = booster.predict(X, output_margin=True)
    df["p"] = np.interp(df["margin"], cal["margin_grid"], cal["p_grid"])
    df["action"] = np.where(df.p >= cal["t_block"], "BLOCK", np.where(df.p >= cal["t_challenge"], "CHALLENGE", "ALLOW"))
    return df


def grouped_shap(df: pd.DataFrame, booster, meta) -> pd.DataFrame:
    dm = xgb.DMatrix(matrix(df, meta["features"], meta["categories"]), enable_categorical=True)
    contrib = booster.get_booster().predict(dm, pred_contribs=True)
    contrib = pd.DataFrame(contrib[:, :-1], columns=meta["features"], index=df.index)
    return pd.DataFrame({g: contrib[[c for c in cols if c in contrib]].sum(axis=1) for g, cols in GROUPS.items()})


def reasons(df: pd.DataFrame, shap_groups: pd.DataFrame, k: int = 3) -> pd.Series:
    out = {}
    for idx, row in df.iterrows():
        s = shap_groups.loc[idx]
        top = s[s > 0].sort_values(ascending=False).head(k)
        out[idx] = [TEMPLATES[g](row) for g in top.index]
    return pd.Series(out)


def plot_global(importance: pd.Series, out_file) -> None:
    labels = {g: g.replace("_", " ") for g in importance.index}
    d = importance.sort_values()
    fig, ax = plt.subplots(figsize=(8, 5.5), facecolor="#fcfcfb")
    ax.set_facecolor("#fcfcfb")
    ax.barh([labels[g] for g in d.index], d.values, color="#2a78d6", height=0.6)
    for y, v in enumerate(d.values):
        ax.text(v, y, f" {v:.2f}", va="center", fontsize=8.5, color="#0b0b0b")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#c3c2b7")
    ax.spines["bottom"].set_color("#c3c2b7")
    ax.tick_params(colors="#52514e")
    ax.grid(axis="x", color="#e1e0d9", linewidth=0.6)
    ax.set_axisbelow(True)
    ax.set_xlabel("mean |SHAP| on flagged logins (log-odds)", color="#52514e")
    ax.set_title("What drives ATO decisions (CHALLENGE / BLOCK, validation)", loc="left", fontweight="bold")
    ax.set_xlim(0, d.max() * 1.15)
    fig.tight_layout()
    fig.savefig(out_file, dpi=130)


def run() -> None:
    booster, meta, cal = load_policy()
    df = score(load("ato", "valid"), booster, meta, cal)
    flagged = df[df.action != "ALLOW"].copy()
    shap_flagged = grouped_shap(flagged, booster, meta)
    flagged["reasons"] = reasons(flagged, shap_flagged)

    coverage = (flagged.reasons.str.len() >= 1).mean()
    full3 = (flagged.reasons.str.len() == 3).mean()
    print(f"validation: {len(df):,} logins; flagged {len(flagged):,} "
          f"(CHALLENGE {int((flagged.action == 'CHALLENGE').sum())}, BLOCK {int((flagged.action == 'BLOCK').sum())}); "
          f"ATO flagged {int(flagged.is_ato.sum())} of {int(df.is_ato.sum())}")
    print(f"reason coverage: {coverage:.1%} have >= 1 reason, {full3:.1%} have 3\n")

    importance = shap_flagged.abs().mean().sort_values(ascending=False)
    print("global importance on flagged logins (mean |SHAP|):")
    print(importance.round(3).to_string(), "\n")

    top1 = shap_flagged.where(shap_flagged > 0).idxmax(axis=1)
    freq = pd.DataFrame({"top_reason_all_flagged": top1.value_counts(normalize=True),
                         "top_reason_ato": top1[flagged.is_ato].value_counts(normalize=True)}).fillna(0)
    print("share of flagged logins whose #1 reason is each group:")
    print(freq.sort_values("top_reason_all_flagged", ascending=False).round(3).to_string(), "\n")

    pd.set_option("display.max_colwidth", 200)
    for title, part in (("caught ATOs", flagged[flagged.is_ato].sort_values("p", ascending=False).head(6)),
                        ("false alarms (BLOCK)", flagged[~flagged.is_ato & (flagged.action == "BLOCK")].head(4)),
                        ("false alarms (CHALLENGE)", flagged[~flagged.is_ato & (flagged.action == "CHALLENGE")].sample(4, random_state=0))):
        print(f"== {title}")
        for r in part.itertuples():
            print(f"  login {r.login_id} {r.country} {r.action} p={r.p:.3f}")
            for i, text in enumerate(r.reasons, 1):
                print(f"     {i}. {text}")
        print()

    figures = ROOT / "docs" / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    plot_global(importance, figures / "shap_global_ato.png")
    print(f"figure saved to {figures / 'shap_global_ato.png'}")


if __name__ == "__main__":
    run()
