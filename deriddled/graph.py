"""Build the IP–account bipartite graph for one month, find credential-stuffing clusters and plot the largest ones."""
import sys

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd

from deriddled.config import ROOT, connect, load_config, path

MIN_USERS_PER_IP = 5
INK, MUTED, SURFACE = "#0b0b0b", "#898781", "#fcfcfb"
ACCOUNT, IP, ATO = "#2a78d6", "#eb6834", "#1baf7a"


def edges(month: str) -> pd.DataFrame:
    src = path(load_config()["data"]["logins_dir"]).as_posix()
    return connect().execute(f"""
        WITH m AS (
            SELECT ip, user_id, asn, country, login_successful, is_attack_ip, is_ato
            FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true)
            WHERE month = '{month}' AND NOT is_non_account
        ),
        busy AS (SELECT ip FROM m GROUP BY ip HAVING COUNT(DISTINCT user_id) >= {MIN_USERS_PER_IP})
        SELECT ip, user_id, ANY_VALUE(asn) AS asn, ANY_VALUE(country) AS country,
               COUNT(*) AS logins, SUM(login_successful::INT) AS successes,
               SUM(is_attack_ip::INT) AS attack_logins, SUM(is_ato::INT) AS ato
        FROM m JOIN busy USING (ip)
        GROUP BY ip, user_id
    """).df()


def clusters(e: pd.DataFrame) -> tuple[nx.Graph, pd.DataFrame]:
    g = nx.Graph()
    g.add_edges_from(zip("ip:" + e.ip, "u:" + e.user_id.astype(str)))
    comp_of = {n: i for i, comp in enumerate(nx.connected_components(g)) for n in comp}
    e = e.assign(component=("ip:" + e.ip).map(comp_of))
    stats = (e.groupby("component")
             .agg(accounts=("user_id", "nunique"), ips=("ip", "nunique"), asns=("asn", "nunique"),
                  countries=("country", "nunique"), logins=("logins", "sum"), successes=("successes", "sum"),
                  attack_logins=("attack_logins", "sum"), ato=("ato", "sum"),
                  top_country=("country", lambda s: s.mode().iat[0]), top_asn=("asn", lambda s: s.mode().iat[0]))
             .sort_values("accounts", ascending=False))
    stats["success_rate"] = stats.successes / stats.logins
    stats["attack_ip_share"] = stats.attack_logins / stats.logins
    return g, stats


def plot(g: nx.Graph, e: pd.DataFrame, stats: pd.DataFrame, out_file, top: int = 4, max_nodes: int = 600) -> None:
    ato_users = set("u:" + e.loc[e.ato > 0, "user_id"].astype(str))
    comp_nodes = list(nx.connected_components(g))
    order = stats.index[:top]
    fig, axes = plt.subplots(1, len(order), figsize=(5 * len(order), 5), facecolor=SURFACE)
    for ax, cid in zip(axes, order):
        nodes = list(comp_nodes[cid])
        if len(nodes) > max_nodes:
            ips = sorted((n for n in nodes if n.startswith("ip:")), key=g.degree, reverse=True)[:30]
            keep = set(ips)
            for ip in ips:
                keep.update(list(g.neighbors(ip))[: max_nodes // len(ips)])
            nodes = list(keep)
        sub = g.subgraph(nodes)
        pos = nx.spring_layout(sub, seed=0, k=0.15)
        colours = [IP if n.startswith("ip:") else ATO if n in ato_users else ACCOUNT for n in sub]
        sizes = [40 if n.startswith("ip:") else 10 for n in sub]
        nx.draw_networkx_edges(sub, pos, ax=ax, edge_color=MUTED, width=0.3, alpha=0.5)
        nx.draw_networkx_nodes(sub, pos, ax=ax, node_color=colours, node_size=sizes, linewidths=0)
        s = stats.loc[cid]
        shown = "" if sub.number_of_nodes() == len(comp_nodes[cid]) else " (30 busiest IPs shown)"
        ax.set_title(f"{int(s.accounts):,} accounts · {int(s.ips)} IPs{shown}\n{s.top_country}, ASN {s.top_asn} · "
                     f"success {s.success_rate:.0%} · attack-IP {s.attack_ip_share:.0%}", fontsize=9, color=INK, loc="left")
        ax.set_axis_off()
    handles = [plt.Line2D([], [], marker="o", ls="", color=c, label=l)
               for c, l in ((IP, "IP address"), (ACCOUNT, "account"), (ATO, "ATO victim"))]
    fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False)
    fig.suptitle("Largest IP–account clusters (IPs touching ≥ 5 accounts)", x=0.01, ha="left", fontweight="bold")
    fig.tight_layout(rect=(0, 0.05, 1, 0.95))
    fig.savefig(out_file, dpi=130)


def run(month: str = "2020-08") -> None:
    e = edges(month)
    g, stats = clusters(e)
    pd.set_option("display.width", 250)
    print(f"{month}: {e.ip.nunique():,} busy IPs, {e.user_id.nunique():,} accounts, {len(e):,} IP–account edges, "
          f"{len(stats):,} components")
    print(f"accounts in largest component: {int(stats.accounts.iat[0]):,} "
          f"({stats.accounts.iat[0] / e.user_id.nunique():.1%} of accounts in the filtered graph)")
    sizes = stats.accounts
    print("component size distribution (accounts):",
          {"1-5": int((sizes <= 5).sum()), "6-20": int(sizes.between(6, 20).sum()),
           "21-100": int(sizes.between(21, 100).sum()), ">100": int((sizes > 100).sum())})
    print(stats.head(10).round(3).to_string())
    print("\ncomponents containing an ATO:")
    print(stats[stats.ato > 0].round(3).to_string())
    figures = ROOT / "docs" / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    plot(g, e, stats, figures / f"ip_account_clusters_{month}.png")
    print(f"\nfigure saved to {figures / f'ip_account_clusters_{month}.png'}")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "2020-08")
