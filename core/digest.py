"""Markdown daily digest."""
import datetime as dt

from .exploits import summary

ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def sort_records(records):
    return sorted(records, key=lambda r: (ORDER[r["priority"]], -(r["epss"] or 0), -(r["cvss"] or 0)))


def build_markdown(records, products, days, today=None):
    today = today or dt.date.today()
    recs = sort_records(records)
    counts = {p: sum(1 for r in recs if r["priority"] == p) for p in ORDER}
    lines = [
        f"# VulnPulse digest - {today}",
        "",
        f"Watchlist: {', '.join(products)}  ",
        f"Window: CVEs published in the last {days} day(s)  ",
        f"Totals: P1={counts['P1']}, P2={counts['P2']}, P3={counts['P3']}, P4={counts['P4']}",
        "",
        "## Needs attention (P1/P2)",
    ]
    urgent = [r for r in recs if r["priority"] in ("P1", "P2")]
    if not urgent:
        lines += ["", "Nothing in P1/P2 for this window."]
    for r in urgent:
        flags = []
        if r["kev"]:
            flags.append(f"KEV (due {r['kev_due']})")
        if r["ransomware"]:
            flags.append("ransomware use")
        epss = f"{r['epss']:.3f}" if r["epss"] is not None else "n/a"
        lines += [
            "",
            f"### {r['id']} - {r['priority']} ({r.get('product', '')})",
            f"CVSS {r['cvss']} | EPSS {epss} | " + (", ".join(flags) or "not in KEV"),
            "",
            r["description"][:400],
            "",
            f"Exploits: {summary(r['exploit'])}",
        ]
    lines += ["", "## Everything else"]
    for r in recs:
        if r["priority"] in ("P3", "P4"):
            lines.append(f"- {r['id']} ({r['priority']}, CVSS {r['cvss']}) - {r.get('product', '')}")
    return "\n".join(lines) + "\n"
