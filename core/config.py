"""Settings: environment variables first, then Streamlit secrets."""
import os
from pathlib import Path

DATA_DIR = Path(os.getenv("VULNPULSE_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "cache.sqlite"
USER_AGENT = "vulnpulse-intel-hub/1.0"

# Cache lifetimes in seconds
TTL = {
    "kev": 6 * 3600,
    "epss": 12 * 3600,
    "nvd": 3600,
    "index": 24 * 3600,
    "github": 12 * 3600,
}


def get_setting(name, default=""):
    val = os.getenv(name)
    if val:
        return val
    try:
        import streamlit as st
        return st.secrets.get(name, default)
    except Exception:
        return default


def nvd_api_key():
    return get_setting("NVD_API_KEY")


def github_token():
    return get_setting("GITHUB_TOKEN")


def risk_calc_url():
    return str(get_setting("RISK_CALC_URL", "https://div-cve-risk-calc.streamlit.app")).rstrip("/")