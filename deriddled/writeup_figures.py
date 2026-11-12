"""Write-up figures on validation: failed attempts before takeovers vs the rule, and the cost curve of the champion's challenge threshold."""
import matplotlib.pyplot as plt
import numpy as np

from deriddled.config import ROOT, load_config
from deriddled.decision import cross_fit, decide, margins, realised_cost, thresholds

BLUE, ORANGE, GREY, INK, MUTED = "#2a78d6", "#eb6834", "#8a8984", "#0b0b0b", "#52514e"


def style(ax) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#c9c8c2")
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(axis="y", color="#ecebe6", linewidth=0.8)
    ax.set_axisbelow(True)


def rule_misses(df, k: int, out) -> None:
    y = df["is_ato"].to_numpy().astype(bool)
    fails = np.minimum(df["user_fails_1h"].fillna(0).to_numpy(), k)
    bins = np.arange(k + 1)
    share = {name: np.array([(fails[mask] == b).mean() for b in bins]) for name, mask in (("ato", y), ("legit", ~y))}
    fig, ax = plt.subplots(figsize=(7, 3.6), dpi=150)
    w = 0.38
    x = np.arange(len(bins))
    ax.bar(x - w / 2 - 0.01, share["legit"] * 100, w, color=BLUE, label="Legitimate logins")
    ax.bar(x + w / 2 + 0.01, share["ato"] * 100, w, color=ORANGE, label=f"Takeovers (n = {y.sum()})")
    for xi, v in zip(x, share["ato"]):
        if v > 0:
            ax.text(xi + w / 2, v * 100 + 1.5, f"{v:.0%}", ha="center", fontsize=8, color=INK)
    ax.axvline(k - 0.5, color=GREY, linestyle="--", linewidth=1)
    ax.text(k - 0.45, 92, f"rule challenges\n≥ {k} fails", fontsize=8, color=MUTED, va="top")
    ax.set_xticks(x, [str(b) for b in bins[:-1]] + [f"{k}+"])
    ax.set_xlabel("Failed password attempts by the user in the previous hour", color=MUTED, fontsize=9)
    ax.set_ylabel("Share of logins (%)", color=MUTED, fontsize=9)
    ax.set_ylim(0, 105)
    ax.set_title("Takeovers arrive with the right password: the rule never sees them", loc="left", fontsize=11, color=INK)
    style(ax)
    ax.legend(frameon=False, fontsize=8, loc="upper center")
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def cost_curve(df, costs: dict, out) -> None:
    y = df["is_ato"].to_numpy().astype(bool)
    p = cross_fit(df, "sigmoid")
    tc, tb = thresholds(costs)
    grid = np.logspace(-5, -1, 60)
    cost = [realised_cost(decide(p, t, max(tb, t)), y, costs)["cost_per_1000"] for t in grid]
    chosen = realised_cost(decide(p, tc, tb), y, costs)
    allow_all = 1000 * costs["c_miss"] * y.sum() / len(y)
    rule_flag = df["user_fails_1h"].fillna(0).to_numpy() >= load_config()["rule_baseline"]["k"]
    rule = realised_cost(np.where(rule_flag, "CHALLENGE", "ALLOW"), y, costs)["cost_per_1000"]

    fig, ax = plt.subplots(figsize=(7, 3.6), dpi=150)
    ax.plot(grid, cost, color=BLUE, linewidth=2, label="De-Riddled, by CHALLENGE threshold")
    ax.axhline(allow_all, color=GREY, linewidth=1, linestyle="--")
    ax.axhline(rule, color=ORANGE, linewidth=1, linestyle="--")
    ax.text(1.3e-2, allow_all + 0.12, f"allow everything: {allow_all:.2f}", fontsize=8, color=MUTED, va="bottom")
    ax.text(1.3e-2, rule + 0.12, f"rule (≥ 5 fails / hour): {rule:.2f}", fontsize=8, color=MUTED, va="bottom")
    ax.plot([tc], [chosen["cost_per_1000"]], "o", markersize=8, color=BLUE, markeredgecolor="white", markeredgewidth=2)
    ax.annotate(f"threshold from the cost model\np ≥ {tc:.5f}: {chosen['cost_per_1000']:.2f}, "
                f"{chosen['challenge_rate']:.3%} challenged",
                (tc, chosen["cost_per_1000"]), xytext=(tc * 3, chosen["cost_per_1000"] + 2.2), fontsize=8, color=INK,
                arrowprops=dict(arrowstyle="-", color=MUTED, linewidth=0.8))
    ax.set_xscale("log")
    ax.set_ylim(0, max(rule, allow_all) * 1.25)
    ax.set_xlabel("CHALLENGE threshold on calibrated p(takeover) (BLOCK fixed at 0.281)", color=MUTED, fontsize=9)
    ax.set_ylabel("Expected cost per 1,000 logins", color=MUTED, fontsize=9)
    ax.set_title("The cost model's threshold sits at the bottom of the curve", loc="left", fontsize=11, color=INK)
    style(ax)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    i = int(np.argmin(cost))
    print(f"curve minimum {cost[i]:.3f} at t = {grid[i]:.2e}; chosen {chosen['cost_per_1000']:.3f} at {tc:.2e}")


def run() -> None:
    cfg = load_config()
    figs = ROOT / "docs" / "figures"
    df = margins("valid", extra=("user_fails_1h",))
    rule_misses(df, cfg["rule_baseline"]["k"], figs / "rule_misses.png")
    cost_curve(df, cfg["costs"], figs / "cost_curve.png")
    print(f"figures written to {figs}")


if __name__ == "__main__":
    run()
