import pandas as pd
import streamlit as st

from core import kev, links
from core.theme import apply_theme

st.set_page_config(page_title="VulnPulse Intel Hub", page_icon="📡", layout="wide")

apply_theme()
st.title("📡 VulnPulse Intel Hub") 
LINKEDIN_URL = "https://www.linkedin.com/in/divyansh-sharma-8113b5113"
PATCHPILOT_URL = "https://patchpilot.streamlit.app/"

st.markdown(
    f'''
    <span style="color:#ffffff;">-By Div</span>
    &nbsp;
    <a href="{LINKEDIN_URL}" target="_blank" rel="noopener noreferrer" title="LinkedIn" style="vertical-align:middle;">
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="#4da3ff">
            <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
        </svg>
    </a>
    ''',
    unsafe_allow_html=True,
)
st.write(
    "Public vulnerability intelligence in one place: watch your products, track CISA KEV deadlines "
    "and check whether a CVE has public exploit code. No logins, no uploads, no user data stored."
)

try:
    df = kev.dataframe()
    c1, c2, c3 = st.columns(3)
    c1.metric("KEV entries", len(df))
    c2.metric("Added in last 30 days", int((df["date_added"] >= pd.Timestamp.now().normalize() - pd.Timedelta(days=30)).sum()))
    c3.metric("Known ransomware use", int(df["ransomware"].sum()))
except Exception as exc:
    st.info(f"KEV snapshot unavailable right now ({exc}).")

st.divider()
a, b, c = st.columns(3)
with a:
    st.page_link("pages/1_Watchlist.py", label="Watchlist digest", icon="📰")
    st.caption("New CVEs for your products, with KEV and EPSS flags.")
with b:
    st.page_link("pages/2_KEV_Dashboard.py", label="KEV dashboard", icon="🚨")
    st.caption("Remediation due dates, filter by vendor or ransomware use.")
with c:
    st.page_link("pages/3_Exploit_Check.py", label="Exploit check", icon="🔎")
    st.caption("PoC, Metasploit, Nuclei and Exploit-DB status for a CVE.")

st.divider()
b1, b2, _ = st.columns([2, 2, 5])
with b1:
    st.link_button("Open Risk Calculator", links.calc_url())
with b2:
    st.link_button("🛠️ Open PatchPilot", PATCHPILOT_URL)
st.caption("Sources: NVD, CISA KEV, FIRST EPSS, Metasploit, Nuclei templates, Exploit-DB, GitHub.")
