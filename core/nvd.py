"""NVD CVE API 2.0 (works without a key, but is slow; add NVD_API_KEY)."""
import datetime as dt
import time

from . import cache, config, http
from .config import TTL

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_last_call = 0.0


def _throttle():
    global _last_call
    gap = 0.7 if config.nvd_api_key() else 6.5
    wait = gap - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.time()


def _request(params):
    _throttle()
    headers = {"apiKey": config.nvd_api_key()} if config.nvd_api_key() else None
    return http.get(NVD_URL, params=params, headers=headers, retry_on=(403, 429, 503)).json()


def _cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity") or m.get("baseSeverity")
    return None, None


def _parse(c):
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score, sev = _cvss(c.get("metrics", {}))
    return {
        "id": c["id"].upper(),
        "published": c.get("published", "")[:10],
        "cvss": score,
        "severity": sev,
        "description": desc,
        "status": c.get("vulnStatus", ""),
    }


def _fmt(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def search_recent(keyword, days=7, limit=200):
    """CVEs published in the last `days` days matching all words in `keyword`."""
    def fetch():
        end = dt.datetime.now(dt.timezone.utc)
        start = end - dt.timedelta(days=days)
        data = _request({
            "keywordSearch": keyword,
            "pubStartDate": _fmt(start),
            "pubEndDate": _fmt(end),
            "resultsPerPage": min(limit, 2000),
        })
        return [_parse(v["cve"]) for v in data.get("vulnerabilities", [])]

    return cache.cached(f"nvd:search:{keyword.lower()}:{days}", TTL["nvd"], fetch)


def get_cve(cve_id):
    cve_id = cve_id.upper()

    def fetch():
        data = _request({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        return _parse(vulns[0]["cve"]) if vulns else None

    return cache.cached(f"nvd:cve:{cve_id}", TTL["nvd"], fetch)
