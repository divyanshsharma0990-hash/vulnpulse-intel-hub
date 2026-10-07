import datetime as dt
import json

import pandas as pd
import streamlit as st

from core import digest, enrich, exploits, links, nvd

st.set_page_config(page_title="Watchlist digest", page_icon="📰", layout="wide")
st.title("📰 Watchlist digest")
st.caption("The list lives only in this browser session. Nothing is stored on the server.")

with st.sidebar:
    days = st.slider("Look back (days)", 1, 30, 7)
    min_cvss = st.slider("Minimum CVSS", 0.0, 10.0, 0.0, 0.5)
    only_flagged = st.checkbox("Only KEV or EPSS >= 0.1")
    use_github = st.checkbox("Include GitHub PoC search (slow, rate-limited)")
    uploaded = st.file_uploader("Load watchlist.json", type="json")

default_text = "Fortinet FortiOS\nApache Log4j"
if uploaded is not None:
    try:
        default_text = "\n".join(json.load(uploaded).get("products", []))
    except Exception:
        st.sidebar.error("Invalid watchlist file")

text = st.text_area("Products (one per line)", default_text, height=140)
products = [p.strip() for p in text.splitlines() if p.strip()]

if st.button("Run digest", type="primary", disabled=not products):
    records, seen = [], set()
    bar = st.progress(0.0, text="Querying NVD...")
    for i, p in enumerate(products):
        try:
            found = nvd.search_recent(p, days)
        except Exception as exc:
            st.warning(f"{p}: NVD lookup failed ({exc})")
            found = []
        for r in found:
            if r["id"] not in seen:
                seen.add(r["id"])
                records.append({**r, "product": p})
        bar.progress((i + 1) / len(products), text=f"Checked {p}")
    with st.spinner("Adding KEV, EPSS and exploit data..."):
        records = enrich.enrich_records(records, include_github=use_github)
    st.session_state["wl"] = {"records": records, "products": products, "days": days}

state = st.session_state.get("wl")
if state:
    recs = [r for r in state["records"] if (r["cvss"] or 0) >= min_cvss]
    if only_flagged:
        recs = [r for r in recs if r["kev"] or (r["epss"] or 0) >= 0.1]
    recs = digest.sort_records(recs)

    cols = st.columns(4)
    for col, p in zip(cols, ["P1", "P2", "P3", "P4"]):
        col.metric(p, sum(1 for r in recs if r["priority"] == p))

    if recs:
        df = pd.DataFrame([
            {
                "Priority": r["priority"],
                "CVE": r["id"],
                "Product": r["product"],
                "CVSS": r["cvss"],
                "EPSS": r["epss"],
                "KEV": r["kev"],
                "Ransomware": r["ransomware"],
                "Exploits": exploits.summary(r["exploit"]),
                "Published": r["published"],
                "NVD": links.nvd_url(r["id"]),
                "Risk calc": links.calc_url(r["id"]),
            }
            for r in recs
        ])
        st.dataframe(
            df,
            hide_index=True,
            column_config={
                "EPSS": st.column_config.NumberColumn(format="%.3f"),
                "NVD": st.column_config.LinkColumn(display_text="Open"),
                "Risk calc": st.column_config.LinkColumn(display_text="Open"),
            },
        )
        with st.expander("Details for P1 / P2"):
            for r in [x for x in recs if x["priority"] in ("P1", "P2")]:
                st.markdown(f"**{r['id']}** ({r['priority']}): {r['description'][:350]}")
    else:
        st.info("No CVEs matched your filters for this window.")

    st.download_button(
        "Download digest (.md)",
        digest.build_markdown(recs, state["products"], state["days"]),
        file_name=f"vulnpulse-digest-{dt.date.today()}.md",
    )
    st.download_button(
        "Download watchlist.json",
        json.dumps({"products": state["products"]}, indent=2),
        file_name="watchlist.json",
    )
