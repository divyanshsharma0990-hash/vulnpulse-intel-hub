"""EPSS scores from FIRST.org (public, no key)."""
from . import cache, http
from .config import TTL

EPSS_URL = "https://api.first.org/data/v1/epss"


def get_epss(cve_ids):
    ids = sorted({c.upper() for c in cve_ids})
    out, missing = {}, []
    for c in ids:
        hit = cache.get(f"epss:{c}", TTL["epss"])
        if hit is not None:
            out[c] = hit
        else:
            missing.append(c)
    for i in range(0, len(missing), 50):
        batch = missing[i:i + 50]
        try:
            rows = http.get(EPSS_URL, params={"cve": ",".join(batch)}).json().get("data", [])
        except Exception:
            continue
        found = {r["cve"].upper(): {"epss": float(r["epss"]), "percentile": float(r["percentile"])} for r in rows}
        for c in batch:
            val = found.get(c, {"epss": None, "percentile": None})
            cache.put(f"epss:{c}", val)
            out[c] = val
    return out
