import pandas as pd
import streamlit as st

from core import kev, links
from core.theme import apply_theme

st.set_page_config(page_title="KEV dashboard", page_icon="🚨", layout="wide")
apply_theme()
st.title("🚨 CISA KEV dashboard")
st.caption("Due dates come from CISA's catalog and apply to US federal agencies (BOD 22-01). "
           "Many organisations use them as a benchmark.")


@st.cache_data(ttl=3600)
def load():
    return kev.dataframe()


try:
    df = load()
except Exception as exc:
    st.error(f"Could not load the KEV catalog: {exc}")
    st.stop()

with st.sidebar:
    vendors = st.multiselect("Vendor", sorted(df["vendor"].unique()))
    ransomware = st.checkbox("Known ransomware use only")
    status = st.radio("Due status", ["All", "Overdue", "Due in 14 days", "Due in 30 days"])
    added_days = st.slider("Added in last N days (0 = all)", 0, 365, 0)

query = st.text_input("Search CVE, product or name")

view = df.copy()
if vendors:
    view = view[view["vendor"].isin(vendors)]
if ransomware:
    view = view[view["ransomware"]]
if status == "Overdue":
    view = view[view["days_left"] < 0]
elif status == "Due in 14 days":
    view = view[view["days_left"].between(0, 14)]
elif status == "Due in 30 days":
    view = view[view["days_left"].between(0, 30)]
if added_days:
    view = view[view["date_added"] >= pd.Timestamp.now().normalize() - pd.Timedelta(days=added_days)]
if query:
    q = query.lower()
    mask = (view["cve"].str.lower().str.contains(q, regex=False)
            | view["product"].str.lower().str.contains(q, regex=False)
            | view["name"].str.lower().str.contains(q, regex=False))
    view = view[mask]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Shown", len(view))
c2.metric("Overdue", int((view["days_left"] < 0).sum()))
c3.metric("Due in 14 days", int(view["days_left"].between(0, 14).sum()))
c4.metric("Ransomware use", int(view["ransomware"].sum()))

out = view.assign(
    NVD=view["cve"].map(links.nvd_url),
    **{"Risk calc": view["cve"].map(links.calc_url)},
)[["cve", "vendor", "product", "name", "date_added", "due_date", "days_left", "ransomware", "NVD", "Risk calc"]]

st.dataframe(
    out,
    hide_index=True,
    column_config={
        "date_added": st.column_config.DateColumn("Added"),
        "due_date": st.column_config.DateColumn("Due"),
        "days_left": st.column_config.NumberColumn("Days left"),
        "NVD": st.column_config.LinkColumn(display_text="Open"),
        "Risk calc": st.column_config.LinkColumn(display_text="Open"),
    },
)
st.download_button("Download filtered CSV", view.to_csv(index=False), file_name="kev-filtered.csv")
