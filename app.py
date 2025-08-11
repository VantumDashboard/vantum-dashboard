import streamlit as st
import pandas as pd
from datetime import datetime, timezone

st.set_page_config(page_title="Vantum — Crypto Threats & Growth Intelligence (Demo)", layout="wide")

from pathlib import Path
import streamlit as st

if Path("vantum-wordmark.svg").exists():
    st.image("vantum-wordmark.svg", width=260)
else:
    st.title("Vantum — Crypto Threats & Growth Intelligence")

st.title("Vantum — Crypto Threats & Growth Intelligence (Demo)")
st.caption("Demo dashboard with sample data. Edit the CSV files in the data/ folder to update the demo anytime.")

# -------- Helpers --------
def load_csv(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path)
        # Parse dates and simple booleans if present
        for col in ["ts", "first_seen", "last_seen"]:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ["risk_flag", "linked_from_social", "shared_funder"]:
            if col in df.columns:
                df[col] = df[col].astype(str).str.lower().isin(["true", "1", "yes"])
        return df
    except Exception as e:
        st.warning(f"Missing or unreadable file: {path} ({e})")
        return pd.DataFrame()

# Load data
flow_spikes = load_csv("data/flow_spikes.csv")
clusters = load_csv("data/clusters.csv")
domains = load_csv("data/domains.csv")
alerts = load_csv("data/alerts.csv")

# Sidebar filters
st.sidebar.title("Filters")
default_chains = ["base", "arbitrum", "solana"]
available_chains = sorted(list({*flow_spikes.get("chain", pd.Series()).dropna().unique(),
                                *clusters.get("chain", pd.Series()).dropna().unique()})) or default_chains
chains = st.sidebar.multiselect("Chains", available_chains, default=available_chains)

# Filtered views
fs = flow_spikes[flow_spikes["chain"].isin(chains)] if not flow_spikes.empty and "chain" in flow_spikes.columns else flow_spikes
cl = clusters[clusters["chain"].isin(chains)] if not clusters.empty and "chain" in clusters.columns else clusters
dm = domains.copy()
al = alerts.copy()

# -------- Overview KPIs --------
def num(x):
    try:
        return float(x)
    except Exception:
        return 0.0

gross_in = fs.loc[fs.get("dir", pd.Series()).str.lower() == "in", "amount_usd"].apply(num).sum() if "dir" in fs.columns else 0.0
gross_out = fs.loc[fs.get("dir", pd.Series()).str.lower() == "out", "amount_usd"].apply(num).sum() if "dir" in fs.columns else 0.0
net_in = gross_in - gross_out
active_clusters = len(cl) if not cl.empty else 0
domains_flagged = int(dm.loc[dm.get("risk_flag", False) == True].shape[0]) if not dm.empty else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Net inflow (USD)", f"{net_in:,.0f}")
col2.metric("Gross inflow (USD)", f"{gross_in:,.0f}")
col3.metric("Active clusters", f"{active_clusters}")
col4.metric("Domains flagged", f"{domains_flagged}")

# Tabs
tab_overview, tab_flows, tab_domains, tab_alerts = st.tabs(
    ["Overview", "Flows & Clusters", "Domains (Brand Safety)", "Recent Alerts"]
)

with tab_overview:
    st.subheader("Top counterparties by net flow")
    if not fs.empty and "entity" in fs.columns:
        df = fs.copy()
        df["amount_usd"] = df["amount_usd"].apply(num)
        df["in_usd"] = df.apply(lambda r: r["amount_usd"] if str(r.get("dir","")).lower()=="in" else 0.0, axis=1)
        df["out_usd"] = df.apply(lambda r: r["amount_usd"] if str(r.get("dir","")).lower()=="out" else 0.0, axis=1)
        top = df.groupby("entity", dropna=False).agg(in_usd=("in_usd","sum"),
                                                     out_usd=("out_usd","sum"))
        top["net_usd"] = top["in_usd"] - top["out_usd"]
        st.dataframe(top.sort_values("net_usd", ascending=False).round(0).head(10), use_container_width=True)
    else:
        st.info("Add rows to data/flow_spikes.csv with an 'entity' column to see this table.")

with tab_flows:
    st.subheader("Recent flow spikes")
    if not fs.empty:
        show_cols = [c for c in ["ts","chain","entity","dir","window","amount_usd","p95_baseline","zscore","evidence_url"] if c in fs.columns]
        st.dataframe(fs.sort_values("ts", ascending=False)[show_cols], use_container_width=True)
    else:
        st.info("No flow spikes yet. Add some to data/flow_spikes.csv.")

    st.subheader("Wallet clusters")
    if not cl.empty:
        show_cols_c = [c for c in ["cluster_id","chain","size","shared_funder","confidence","first_seen","last_seen","features"] if c in cl.columns]
        st.dataframe(cl.sort_values("confidence", ascending=False)[show_cols_c], use_container_width=True)
    else:
        st.info("No clusters yet. Add some to data/clusters.csv.")

with tab_domains:
    st.subheader("New domains and impersonations")
    if not dm.empty:
        show_cols_d = [c for c in ["domain","matched_term","first_seen","risk_flag","linked_from_social","registrar","ssl_issuer","urlscan_url"] if c in dm.columns]
        st.dataframe(dm.sort_values("first_seen", ascending=False)[show_cols_d], use_container_width=True)
    else:
        st.info("No domains yet. Add some to data/domains.csv.")

with tab_alerts:
    st.subheader("Recent alerts")
    if not al.empty:
        show_cols_a = [c for c in ["ts","severity","rule","subject","confidence","evidence_url","meta"] if c in al.columns]
        st.dataframe(al.sort_values("ts", ascending=False)[show_cols_a], use_container_width=True)
    else:
        st.info("No alerts yet. Add some to data/alerts.csv.")

st.caption("Tip: edit the CSV files in GitHub (data/*.csv), then refresh this page to update the demo.")
