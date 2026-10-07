"""Join NVD + KEV + EPSS + exploit data and assign a simple P1-P4 priority.

This is an intentionally simple heuristic. Plug your Risk Calculator scoring in here
if you want both apps to use the same logic.
"""
from . import epss, exploits, kev


def priority(cvss, epss_score, in_kev, has_exploit):
    cvss = cvss or 0
    epss_score = epss_score or 0
    if in_kev or (epss_score >= 0.5 and cvss >= 7):
        return "P1"
    if epss_score >= 0.1 or (has_exploit and cvss >= 7):
        return "P2"
    if cvss >= 7 or epss_score >= 0.01:
        return "P3"
    return "P4"


def enrich_records(records, include_github=False):
    kev_idx = kev.kev_index()
    epss_map = epss.get_epss([r["id"] for r in records])
    for r in records:
        k = kev_idx.get(r["id"])
        r["kev"] = bool(k)
        r["kev_due"] = k.get("dueDate") if k else None
        r["ransomware"] = bool(k and k.get("knownRansomwareCampaignUse") == "Known")
        e = epss_map.get(r["id"], {})
        r["epss"] = e.get("epss")
        r["epss_pct"] = e.get("percentile")
        r["exploit"] = exploits.check(r["id"], include_github=include_github)
        r["priority"] = priority(r["cvss"], r["epss"], r["kev"], r["exploit"]["any"])
    return records
