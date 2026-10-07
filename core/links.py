"""Links to the Risk Calculator app (separate repo / separate deployment)."""
from urllib.parse import quote

from . import config


def calc_url(cve=None):
    base = config.risk_calc_url()
    return f"{base}/?cve={quote(cve)}" if cve else base


def nvd_url(cve):
    return f"https://nvd.nist.gov/vuln/detail/{cve}"
