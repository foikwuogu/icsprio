"""Streamlit dashboard for viewing icsprio's pipeline output.

Reads the already-generated `data/processed/` artifacts (it never fetches
or re-scores anything itself) and renders them for interactive review:
KPI summary, QA report, join match rates, priority-band breakdown, and a
filterable table of the joined (advisory, CVE) rows.

Run with:
    streamlit run dashboard.py
"""

from __future__ import annotations

import json
import os

import pandas as pd
import streamlit as st

from icsprio import config

st.set_page_config(page_title="icsprio dashboard", layout="wide")

PROCESSED_DIR = config.DEFAULT_PROCESSED_DIR
CSV_PATH = os.path.join(PROCESSED_DIR, "icsprio_joined.csv")
PARQUET_PATH = os.path.join(PROCESSED_DIR, "icsprio_joined.parquet")
STATS_PATH = os.path.join(PROCESSED_DIR, "stats.json")
QA_REPORT_PATH = os.path.join(PROCESSED_DIR, "qa_report.txt")

BAND_ORDER = ["Critical", "High", "Medium", "Low"]
BAND_COLORS = {"Critical": "#b91c1c", "High": "#d97706", "Medium": "#2563eb", "Low": "#6b7280"}


@st.cache_data
def load_data(csv_mtime: float, parquet_mtime: float) -> pd.DataFrame:
    """Cache keyed on file mtimes, so a fresh `icsprio run` invalidates it
    without needing a manual cache-clear."""
    if os.path.exists(PARQUET_PATH):
        try:
            return pd.read_parquet(PARQUET_PATH)
        except (ImportError, ValueError):
            pass
    return pd.read_csv(CSV_PATH)


def _mtime(path: str) -> float:
    return os.path.getmtime(path) if os.path.exists(path) else 0.0


if not os.path.exists(CSV_PATH):
    st.title("icsprio dashboard")
    st.error(
        f"No output found at `{CSV_PATH}`. Run `python -m icsprio run` (or `icsprio build`) first."
    )
    st.stop()

df = load_data(_mtime(CSV_PATH), _mtime(PARQUET_PATH))

stats = {}
if os.path.exists(STATS_PATH):
    with open(STATS_PATH, encoding="utf-8") as f:
        stats = json.load(f)

st.title("icsprio dashboard")
st.caption("ICS vulnerability intelligence — CISA ICS advisories x KEV x EPSS x Vulnrichment x ATT&CK for ICS")
if stats.get("generated_at"):
    st.caption(f"Report generated: {stats['generated_at']}")

# --- Sidebar filters --------------------------------------------------------

st.sidebar.header("Filters")

bands_present = [b for b in BAND_ORDER if b in df["priority_band"].unique()]
selected_bands = st.sidebar.multiselect("Priority band", bands_present, default=bands_present)

adv_types = sorted(df["advisory_type"].dropna().unique())
selected_types = st.sidebar.multiselect("Advisory type", adv_types, default=adv_types)

kev_only = st.sidebar.checkbox("KEV entries only", value=False)

vendor_query = st.sidebar.text_input("Vendor contains")

min_score, max_score = st.sidebar.slider("Priority score range", 0, 100, (0, 100))

filtered = df[
    df["priority_band"].isin(selected_bands)
    & df["advisory_type"].isin(selected_types)
    & df["priority_score"].fillna(-1).between(min_score, max_score)
]
if kev_only:
    filtered = filtered[filtered["in_kev"] == True]  # noqa: E712
if vendor_query:
    filtered = filtered[filtered["vendors"].astype(str).str.contains(vendor_query, case=False, na=False)]

# --- KPI row -----------------------------------------------------------------

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Rows (filtered)", f"{len(filtered):,}", help=f"of {len(df):,} total")
col2.metric("Unique advisories", f"{filtered['advisory_id'].nunique():,}")
col3.metric("Unique CVEs", f"{filtered['cve'].nunique():,}")
col4.metric("In KEV", f"{int((filtered['in_kev'] == True).sum()):,}")  # noqa: E712
col5.metric("Critical", f"{int((filtered['priority_band'] == 'Critical').sum()):,}")

st.divider()

# --- Charts ------------------------------------------------------------------

chart_col, rate_col = st.columns([2, 1])

with chart_col:
    st.subheader("Priority band distribution")
    band_counts = (
        filtered["priority_band"].value_counts().reindex(BAND_ORDER).dropna().rename("count")
    )
    st.bar_chart(band_counts, color=None)

with rate_col:
    st.subheader("Join match rates")
    rates = stats.get("join_match_rates", {})
    if rates:
        st.dataframe(
            pd.DataFrame({"rate": rates}).style.format("{:.1%}"),
            width="stretch",
        )
    else:
        st.caption("No stats.json found.")

st.subheader("Top vendors by row count (filtered)")
if not filtered.empty:
    vendor_counts = (
        filtered["vendors"].astype(str).str.split(r"\s*;\s*").explode().value_counts().head(15)
    )
    st.bar_chart(vendor_counts)
else:
    st.caption("No rows match the current filters.")

st.divider()

# --- Data table ---------------------------------------------------------------

st.subheader(f"Joined rows ({len(filtered):,})")
st.dataframe(
    filtered.sort_values("priority_score", ascending=False, na_position="last"),
    width="stretch",
    height=500,
)
st.download_button(
    "Download filtered rows as CSV",
    filtered.to_csv(index=False).encode("utf-8"),
    file_name="icsprio_filtered.csv",
    mime="text/csv",
)

# --- QA report -----------------------------------------------------------------

if os.path.exists(QA_REPORT_PATH):
    with st.expander("Full QA report (docs/VERIFY_CHECKLIST.md gate)"):
        with open(QA_REPORT_PATH, encoding="utf-8") as f:
            st.text(f.read())
