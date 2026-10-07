"""CISA Known Exploited Vulnerabilities catalog."""
import pandas as pd

from . import cache, http
from .config import TTL

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_kev():
    return cache.cached("kev", TTL["kev"], lambda: http.get(KEV_URL).json().get("vulnerabilities", []))


def kev_index():
    return {v["cveID"].upper(): v for v in load_kev()}


def dataframe():
    rows = [
        {
            "cve": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "description": v.get("shortDescription", ""),
            "required_action": v.get("requiredAction", ""),
        }
        for v in load_kev()
    ]
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["date_added"] = pd.to_datetime(df["date_added"], errors="coerce")
    df["due_date"] = pd.to_datetime(df["due_date"], errors="coerce")
    today = pd.Timestamp.now().normalize()
    df["days_left"] = (df["due_date"] - today).dt.days
    return df.sort_values("date_added", ascending=False).reset_index(drop=True)
