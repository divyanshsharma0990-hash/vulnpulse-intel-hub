# VulnPulse Intel Hub

Public vulnerability intelligence in one Streamlit app. No logins, no uploads, no user data stored.

- **Watchlist digest**: new CVEs for your products (NVD), flagged with CISA KEV and EPSS, exported as a Markdown digest
- **KEV dashboard**: remediation due dates, filter by vendor, ransomware use, overdue status
- **Exploit check**: Metasploit, Nuclei, Exploit-DB and GitHub PoC signals for one CVE

Companion project: **VulnPulse Risk Calculator** (separate repo). The two apps link to each other by URL.

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .streamlit/secrets.toml.example .streamlit/secrets.toml   # add NVD_API_KEY
streamlit run app.py --server.port 8502
```
Run the Risk Calculator on port 8501 (`streamlit run app.py`) so the links work.

## Settings (env vars or .streamlit/secrets.toml)
| Name | Purpose |
|---|---|
| NVD_API_KEY | Free key, makes NVD calls about 10x faster |
| GITHUB_TOKEN | Optional, raises GitHub search rate limit |
| RISK_CALC_URL | Where the Risk Calculator is hosted |

## Daily digest from the command line
```bash
cp watchlist.example.json watchlist.json
python digest.py --days 1 --out digest.md     # schedule with cron or Task Scheduler
```

## Linking with the Risk Calculator
Hub to calculator: every CVE row has a "Risk calc" link to `RISK_CALC_URL/?cve=CVE-XXXX-YYYY`.

Calculator to hub: add this to the calculator's `app.py`:
```python
import os
import streamlit as st

HUB_URL = os.getenv("INTEL_HUB_URL", "http://localhost:8502")

prefill = st.query_params.get("cve", "")
cve_id = st.text_input("CVE ID", value=prefill)   # use this in place of your current input

if cve_id:
    st.link_button("View exploit and KEV details in Intel Hub", f"{HUB_URL}/Exploit_Check?cve={cve_id}")
```

## Data sources
NVD CVE API 2.0, CISA KEV, FIRST EPSS, Metasploit module metadata, ProjectDiscovery nuclei-templates, Exploit-DB, GitHub search.
Public data only. GitHub PoC repos are unverified; review before use and only run them in an isolated lab.

## Notes
- First run downloads the Metasploit and Exploit-DB indexes (tens of MB) and caches them in `data/` (git-ignored) for 24h.
- Priority is a simple heuristic (`core/enrich.py`). Replace it with your calculator's scoring to keep both apps consistent.
