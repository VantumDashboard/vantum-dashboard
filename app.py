import streamlit as st
import pandas as pd
import json
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path

st.set_page_config(page_title="Vantum — Crypto Threats & Growth Intelligence (MVP)", layout="wide")

# ---------- Branding ----------
if Path("vantum-wordmark.svg").exists():
    st.image("vantum-wordmark.svg", width=260)

st.title("Vantum — Crypto Threats & Growth Intelligence")
st.caption("Live MVP: pulls real on‑chain data when configured; falls back to demo CSVs if not.")

# ---------- Secrets / Config ----------
SECRETS = st.secrets
CONTACT_EMAIL = SECRETS.get("contact", {}).get("EMAIL", "crypto@addprivacy.net")

CLIENT_NAME = SECRETS.get("client", {}).get("NAME", "Demo Protocol")
CHAINS = [c.strip().lower() for c in SECRETS.get("client", {}).get("CHAINS", "base").split(",") if c.strip()]
try:
    CONTRACTS = json.loads(SECRETS.get("client", {}).get("CONTRACTS_JSON", "[]"))
except Exception:
    CONTRACTS = []
try:
    ADDRESSES = [a.lower() for a in json.loads(SECRETS.get("client", {}).get("ADDRESSES_JSON", "[]"))]
except Exception:
    ADDRESSES = []

COVALENT_KEY = SECRETS.get("apis", {}).get("COVALENT_KEY", "")
URLSCAN_KEY = SECRETS.get("apis", {}).get("URLSCAN_KEY", "")
BASESCAN_KEY = SECRETS.get("apis", {}).get("BASESCAN_KEY", "")
ARBISCAN_KEY = SECRETS.get("apis", {}).get("ARBISCAN_KEY", "")

SLACK_WEBHOOK = SECRETS.get("alerts", {}).get("SLACK_WEBHOOK", "")
DISCORD_WEBHOOK = SECRETS.get("alerts", {}).get("DISCORD_WEBHOOK", "")

# Basic chain IDs for Covalent
CHAIN_IDS = {
    "base": 8453,
    "arbitrum": 42161,
    "ethereum": 1,
    "polygon": 137,
    "optimism": 10,
}

# Etherscan-family explorer endpoints (free)
CHAIN_SCANS = {
    "base": {"url": "https://api.basescan.org/api", "key": BASESCAN_KEY},
    "arbitrum": {"url": "https://api.arbiscan.io/api", "key": ARBISCAN_KEY},
}

STABLE_TOKENS = {"USDC", "USDbC", "USDC.E", "USDT", "DAI", "USD+"}

# ---------- Sidebar ----------
st.sidebar.title("Get started")
st.sidebar.markdown("**Book a 2‑week pilot (£700)**")
st.sidebar.write(f"[Email us](mailto:{CONTACT_EMAIL}?subject=Vantum%20Pilot)")
st.sidebar.checkbox("Show disclaimer", value=True, key="show_disclaimer")
st.sidebar.divider()

has_covalent = bool(COVALENT_KEY)
has_scan = any(d.get("key") for d in CHAIN_SCANS.values())
default_live = bool((has_covalent or has_scan) and ADDRESSES)
st.sidebar.title("Live data")
use_live = st.sidebar.checkbox("Use live on‑chain data", value=default_live)
lookback_hours = st.sidebar.slider("Lookback (hours)", 2, 48, 24)
abs_30m_usd = st.sidebar.number_input("30m spike threshold (USD)", min_value=10000, value=100000, step=10000)
abs_24h_usd = st.sidebar.number_input("24h spike threshold (USD)", min_value=100000, value=500000, step=50000)

if use_live:
    if has_covalent:
        st.sidebar.success("Data source: Covalent (auto)")
    elif has_scan:
        st.sidebar.success("Data source: Block explorers (BaseScan/Arbiscan)")
    else:
        st.sidebar.warning("No API keys found. Add Covalent or BaseScan/Arbiscan keys in Secrets.")

# ---------- Helpers ----------
def load_csv(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path)
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

@st.cache_data(ttl=300, show_spinner=False)
def get_eth_usd() -> float:
    try:
        r = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": "ethereum", "vs_currencies": "usd"},
            timeout=15,
        )
        r.raise_for_status()
        return float(r.json()["ethereum"]["usd"])
    except Exception:
        return 0.0

@st.cache_data(ttl=300, show_spinner=False)
def fetch_covalent_tx(chain: str, address: str, page_size: int = 200):
    chain_id = CHAIN_IDS.get(chain)
    if not chain_id:
        return []
    url = f"https://api.covalenthq.com/v1/{chain_id}/address/{address}/transactions_v3/"
    params = {"key": COVALENT_KEY, "page-size": page_size}
    try:
        r = requests.get(url, params=params, timeout=30)
        r.raise_for_status()
        data = r.json() or {}
        items = data.get("data", {}).get("items", data.get("items", [])) or []
        out = []
        for it in items:
            ts = it.get("block_signed_at") or it.get("timestamp") or it.get("signed_at")
            tx_hash = it.get("tx_hash") or it.get("hash")
            from_addr = (it.get("from_address") or "").lower()
            to_addr = (it.get("to_address") or "").lower()
            amount_usd = it.get("value_quote") or it.get("value_quote_sum") or 0
            out.append({"ts": ts, "tx_hash": tx_hash, "from_addr": from_addr, "to_addr": to_addr, "amount_usd": amount_usd})
        return out
    except Exception:
        return []

@st.cache_data(ttl=300, show_spinner=False)
def fetch_scan_txlist(chain: str, address: str, offset: int = 200):
    cfg = CHAIN_SCANS.get(chain)
    if not cfg or not cfg["key"]:
        return []
    try:
        r = requests.get(cfg["url"], params={
            "module": "account",
            "action": "txlist",
            "address": address,
            "page": 1,
            "offset": offset,
            "sort": "desc",
            "apikey": cfg["key"],
        }, timeout=30)
        data = r.json()
        if str(data.get("status")) != "1":
            return []
        return data.get("result", [])
    except Exception:
        return []

@st.cache_data(ttl=300, show_spinner=False)
def fetch_scan_tokentx(chain: str, address: str, offset: int = 200):
    cfg = CHAIN_SCANS.get(chain)
    if not cfg or not cfg["key"]:
        return []
    try:
        r = requests.get(cfg["url"], params={
            "module": "account",
            "action": "tokentx",
            "address": address,
            "page": 1,
            "offset": offset,
            "sort": "desc",
            "apikey": cfg["key"],
        }, timeout=30)
        data = r.json()
        if str(data.get("status")) != "1":
            return []
        return data.get("result", [])
    except Exception:
        return []

def normalize_tx(rows):
    if not rows:
        return pd.DataFrame(columns=["ts","tx_hash","from_addr","to_addr","amount_usd"])
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
    df["amount_usd"] = pd.to_numeric(df["amount_usd"], errors="coerce").fillna(0.0)
    df["from_addr"] = df["from_addr"].astype(str).str.lower()
    df["to_addr"] = df["to_addr"].astype(str).str.lower()
    return df.dropna(subset=["ts"])

def build_flows_covalent(chain: str, addrs: list[str], hours_back: int) -> pd.DataFrame:
    all_rows = []
    for addr in addrs:
        rows = fetch_covalent_tx(chain, addr, page_size=200)
        for r in rows:
            r["chain"] = chain
        all_rows.extend(rows)
    df = normalize_tx(all_rows)
    if df.empty:
        return df
    cutoff = pd.Timestamp.utcnow().tz_localize("UTC") - timedelta(hours=hours_back)
    df = df[df["ts"] >= cutoff].copy()

    df_in = df[df["to_addr"].isin(addrs)].copy()
    df_in["dir"] = "in"
    df_in["entity"] = df_in["from_addr"]

    df_out = df[df["from_addr"].isin(addrs)].copy()
    df_out["dir"] = "out"
    df_out["entity"] = df_out["to_addr"]

    return pd.concat([df_in, df_out], ignore_index=True)

def build_flows_scan(chain: str, addrs: list[str], hours_back: int) -> pd.DataFrame:
    eth_usd = get_eth_usd()
    if eth_usd <= 0:
        eth_usd = 3000.0  # sane fallback

    rows = []
    addrs_set = set(a.lower() for a in addrs)
    cutoff = pd.Timestamp.utcnow().tz_localize("UTC") - timedelta(hours=hours_back)

    for addr in addrs:
        # Native transfers
        txs = fetch_scan_txlist(chain, addr, offset=200)
        for t in txs:
            try:
                ts = pd.to_datetime(int(t.get("timeStamp", "0")), unit="s", utc=True)
            except Exception:
                continue
            if ts < cutoff:
                continue
            tx_hash = t.get("hash", "")
            from_addr = (t.get("from", "") or "").lower()
            to_addr = (t.get("to", "") or "").lower()
            value_wei = int(t.get("value", "0"))
            value_eth = value_wei / 1e18
            amount_usd = value_eth * eth_usd
            rows.append({"ts": ts, "tx_hash": tx_hash, "from_addr": from_addr, "to_addr": to_addr, "amount_usd": amount_usd, "chain": chain})
        # Token transfers (stablecoins, WETH)
        toks = fetch_scan_tokentx(chain, addr, offset=200)
        for t in toks:
            try:
                ts = pd.to_datetime(int(t.get("timeStamp", "0")), unit="s", utc=True)
            except Exception:
                continue
            if ts < cutoff:
                continue
            token_symbol = str(t.get("tokenSymbol", "")).upper()
            decimals = int(t.get("tokenDecimal", "18") or "18")
            raw = t.get("value", "0")
            try:
                value = int(raw) / (10 ** decimals)
            except Exception:
                value = 0.0
            if token_symbol in STABLE_TOKENS:
                amount_usd = value
            elif token_symbol in {"WETH", "ETH"}:
                amount_usd = value * eth_usd
            else:
                # Skip obscure tokens to avoid noisy USD estimates
                continue
            tx_hash = t.get("hash", "")
            from_addr = (t.get("from", "") or "").lower()
            to_addr = (t.get("to", "") or "").lower()
            rows.append({"ts": ts, "tx_hash": tx_hash, "from_addr": from_addr, "to_addr": to_addr, "amount_usd": amount_usd, "chain": chain})

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["from_addr"] = df["from_addr"].astype(str).str.lower()
    df["to_addr"] = df["to_addr"].astype(str).str.lower()

    df_in = df[df["to_addr"].isin(addrs_set)].copy()
    df_in["dir"] = "in"
    df_in["entity"] = df_in["from_addr"]

    df_out = df[df["from_addr"].isin(addrs_set)].copy()
    df_out["dir"] = "out"
    df_out["entity"] = df_out["to_addr"]

    return pd.concat([df_in, df_out], ignore_index=True)

def detect_spikes(flows: pd.DataFrame, window_minutes: int, abs_threshold: float) -> pd.DataFrame:
    if flows.empty:
        return pd.DataFrame()
    cutoff = pd.Timestamp.utcnow().tz_localize("UTC") - timedelta(minutes=window_minutes)
    f = flows[flows["ts"] >= cutoff].copy()
    g = f.groupby(["chain","entity","dir"], dropna=False)["amount_usd"].sum().reset_index()
    g = g[g["amount_usd"] >= abs_threshold].copy()
    if g.empty:
        return pd.DataFrame()
    g["window"] = f"{window_minutes}m" if window_minutes < 120 else "24h"
    g["ts"] = pd.Timestamp.utcnow().tz_localize("UTC")
    g["p95_baseline"] = None
    g["zscore"] = None
    g["evidence_url"] = ""
    return g[["ts","chain","entity","dir","window","amount_usd","p95_baseline","zscore","evidence_url"]]

@st.cache_data(ttl=300, show_spinner=False)
def search_urlscan(terms: list[str], limit: int = 25) -> pd.DataFrame:
    if not terms:
        return pd.DataFrame()
    results = []
    headers = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    for term in terms[:3]:
        try:
            q = f"https://urlscan.io/api/v1/search/?q={term}"
            r = requests.get(q, headers=headers, timeout=20)
            if r.status_code != 200:
                continue
            data = r.json() or {}
            for res in data.get("results", [])[:limit]:
                page = res.get("page", {})
                task = res.get("task", {})
                domain = page.get("domain", "")
                urlscan_url = task.get("reportURL", "")
                ts = task.get("time")
                results.append({
                    "domain": domain,
                    "matched_term": term,
                    "first_seen": ts,
                    "risk_flag": True if term.lower() in str(domain).lower() else False,
                    "linked_from_social": False,
                    "registrar": "",
                    "ssl_issuer": "",
                    "urlscan_url": urlscan_url
                })
        except Exception:
            continue
    if not results:
        return pd.DataFrame()
    df = pd.DataFrame(results)
    df["first_seen"] = pd.to_datetime(df["first_seen"], utc=True, errors="coerce")
    return df.sort_values("first_seen", ascending=False).drop_duplicates(subset=["domain"])

def build_alerts_from_spikes(spikes_30m: pd.DataFrame, spikes_24h: pd.DataFrame) -> pd.DataFrame:
    rows = []
    now = pd.Timestamp.utcnow().tz_localize("UTC")
    for df, window in [(spikes_30m, "30m"), (spikes_24h, "24h")]:
        if df is None or df.empty:
            continue
        for _, r in df.iterrows():
            severity = "critical" if r["amount_usd"] >= (abs_24h_usd if window=="24h" else abs_30m_usd) else "warning"
            confidence = 0.8 if severity == "critical" else 0.7
            subject = ("Inflow spike" if r["dir"] == "in" else "Outflow spike") + f" — {r['entity'][:10]}… on {r['chain']}"
            rows.append({
                "ts": now,
                "severity": severity.title(),
                "rule": "inflow_spike" if r["dir"]=="in" else "outflow_spike",
                "subject": subject,
                "confidence": confidence,
                "evidence_url": "",
                "meta": json.dumps({"entity": r["entity"], "amount_usd": float(r["amount_usd"]), "window": window})
            })
    return pd.DataFrame(rows)

# ---------- Data sourcing ----------
if use_live and ADDRESSES and (has_covalent or has_scan):
    flows_all = []
    for ch in CHAINS:
        if has_covalent:
            flows = build_flows_covalent(ch, ADDRESSES, lookback_hours)
        else:
            flows = build_flows_scan(ch, ADDRESSES, lookback_hours)
        if not flows.empty:
            flows_all.append(flows)
    df_flows = pd.concat(flows_all, ignore_index=True) if flows_all else pd.DataFrame()

    fs_30 = detect_spikes(df_flows, window_minutes=30, abs_threshold=abs_30m_usd)
    fs_24 = detect_spikes(df_flows, window_minutes=24*60, abs_threshold=abs_24h_usd)
    flow_spikes = pd.concat([fs_30, fs_24], ignore_index=True) if (fs_30 is not None or fs_24 is not None) else pd.DataFrame()

    brand_terms = [CLIENT_NAME.split()[0]] if CLIENT_NAME else []
    domains = search_urlscan(brand_terms)

    clusters = pd.DataFrame(columns=["cluster_id","chain","size","shared_funder","confidence","first_seen","last_seen","features"])
    alerts = build_alerts_from_spikes(fs_30, fs_24)
else:
    flow_spikes = load_csv("data/flow_spikes.csv")
    clusters = load_csv("data/clusters.csv")
    domains = load_csv("data/domains.csv")
    alerts = load_csv("data/alerts.csv")

# ---------- Filters ----------
st.sidebar.title("Filters")
default_chains = ["base", "arbitrum", "solana"]
available_chains = sorted(list({
    *flow_spikes.get("chain", pd.Series()).dropna().unique(),
    *clusters.get("chain", pd.Series()).dropna().unique()
})) or default_chains
chains = st.sidebar.multiselect("Chains", available_chains, default=available_chains)

# Filtered views
fs = flow_spikes[flow_spikes["chain"].isin(chains)] if not flow_spikes.empty and "chain" in flow_spikes.columns else flow_spikes
cl = clusters[clusters["chain"].isin(chains)] if not clusters.empty and "chain" in clusters.columns else clusters
dm = domains.copy()
al = alerts.copy()

# ---------- KPIs ----------
def num(x):
    try:
        return float(x)
    except Exception:
        return 0.0

gross_in = fs.loc[fs.get("dir", pd.Series()).str.lower() == "in", "amount_usd"].apply(num).sum() if "dir" in fs.columns else 0.0
gross_out = fs.loc[fs.get("dir", pd.Series()).str.lower() == "out", "amount_usd"].apply(num).sum() if "dir" in fs.columns else 0.0
net_in = gross_in - gross_out
active_clusters = len(cl) if not cl.empty else 0
domains_flagged = int(pd.Series(dm["risk_flag"]).astype(bool).sum()) if ("risk_flag" in dm.columns and not dm.empty) else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Net inflow (USD)", f"{net_in:,.0f}")
col2.metric("Gross inflow (USD)", f"{gross_in:,.0f}")
col3.metric("Active clusters", f"{active_clusters}")
col4.metric("Domains flagged", f"{domains_flagged}")

# ---------- Tabs ----------
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
        st.info("No flow data yet. Add client ADDRESSES and an API key in Secrets, then enable live mode.")

with tab_flows:
    st.subheader("Recent flow spikes")
    if not fs.empty:
        show_cols = [c for c in ["ts","chain","entity","dir","window","amount_usd","p95_baseline","zscore","evidence_url"] if c in fs.columns]
        st.dataframe(fs.sort_values("ts", ascending=False)[show_cols], use_container_width=True)
    else:
        st.info("No flow spikes yet.")

    st.subheader("Wallet clusters")
    if not cl.empty:
        show_cols_c = [c for c in ["cluster_id","chain","size","shared_funder","confidence","first_seen","last_seen","features"] if c in cl.columns]
        st.dataframe(cl.sort_values("confidence", ascending=False)[show_cols_c], use_container_width=True)
    else:
        st.info("Clusters will appear in Pro (deeper heuristics).")

with tab_domains:
    st.subheader("New domains and impersonations")
    if not dm.empty:
        show_cols_d = [c for c in ["domain","matched_term","first_seen","risk_flag","linked_from_social","registrar","ssl_issuer","urlscan_url"] if c in dm.columns]
        st.dataframe(dm.sort_values("first_seen", ascending=False)[show_cols_d], use_container_width=True)
    else:
        st.info("No domain matches yet. Set client NAME to help the search.")

with tab_alerts:
    st.subheader("Recent alerts")
    if not al.empty:
        show_cols_a = [c for c in ["ts","severity","rule","subject","confidence","evidence_url","meta"] if c in al.columns]
        st.dataframe(al.sort_values("ts", ascending=False)[show_cols_a], use_container_width=True)
    else:
        st.info("No alerts in this window.")

# Footer
st.markdown("---")
cta = st.columns([3,1])[1]
with cta:
    st.subheader("Book a 2‑week pilot (£700)")
    st.write(f"Email: {CONTACT_EMAIL}")
    st.write("Includes live dashboard, alerts under 10 minutes, and a weekly 1‑page brief. If you don’t see value, don’t roll.")

if st.session_state.get("show_disclaimer", True):
    st.caption("Public data only. No investment advice. Sources and timestamps logged.")
