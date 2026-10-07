import pandas as pd
import streamlit as st

from core import kev, links

st.set_page_config(page_title="VulnPulse Intel Hub", page_icon="📡", layout="wide")
st.title("📡 VulnPulse Intel Hub") 
("-By Div")
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
st.link_button("Open Risk Calculator", links.calc_url())
st.caption("Sources: NVD, CISA KEV, FIRST EPSS, Metasploit, Nuclei templates, Exploit-DB, GitHub.")
