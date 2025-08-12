import streamlit as st
import pandas as pd
import json
import requests
from datetime import timedelta
from pathlib import Path

st.set_page_config(page_title="Vantum — Crypto Threats & Growth Intelligence (MVP)", layout="wide")

# ---------- Branding ----------
if Path("vantum-wordmark.svg").exists():
    st.image("vantum-wordmark.svg", width=260)

st.title("Crypto Threats & Growth Intelligence")
st.caption("Live MVP: pulls real on‑chain data when configured to your project.")

# ---------- Secrets / Config ----------
SECRETS = st.secrets
CONTACT_EMAIL = SECRETS.get("contact", {}).get("EMAIL", "crypto@addprivacy.net")

CLIENT_NAME = SECRETS.get("client", {}).get("NAME", "Demo Protocol")
CHAINS = [c.strip().lower() for c in SECRETS.get("client", {}).get("CHAINS", "base").split(",") if c.strip()]

# Optional: allow brand terms list via JSON; else default to first word of client name
try:
    BRAND_TERMS = json.loads(SECRETS.get("client", {}).get("BRAND_TERMS_JSON", "[]"))
    if not isinstance(BRAND_TERMS, list):
        BRAND_TERMS = []
except Exception:
    BRAND_TERMS = []
if not BRAND_TERMS:
    BRAND_TERMS = [CLIENT_NAME.split()[0]] if CLIENT_NAME else []

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
ZAPIER_WEBHOOK = SECRETS.get("alerts", {}).get("ZAPIER_WEBHOOK", "")

# ---------- Chain constants ----------
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

# Public explorer TX URL bases for evidence links
SCAN_TX_BASE = {
    "base": "https://basescan.org/tx/",
    "arbitrum": "https://arbiscan.io/tx/",
    "ethereum": "https://etherscan.io/tx/",
    "polygon": "https://polygonscan.com/tx/",
    "optimism": "https://optimistic.etherscan.io/tx/",
}

STABLE_TOKENS = {"USDC", "USDBC", "USDC.E", "USDT", "DAI", "USD+"}

# ---------- Token pricing for project token(s) ----------
# Coingecko platform ids for token prices by chain
COINGECKO_PLATFORMS = {
    "base": "base",
    "arbitrum": "arbitrum-one",
    "ethereum": "ethereum",
    "polygon": "polygon-pos",
    "optimism": "optimistic-ethereum",
}

# Whitelisted project tokens we want USD prices for (by contract address, lowercase)
# Aerodrome AERO on Base so flows to/from VotingEscrow/RewardsDistributor are valued
WHITELIST_TOKENS = {
    "base": {
        "0x940181a94a35a4569e4529a3cdfb74e38fd98631": "AERO"
    }
}

# ---------- Sidebar ----------
st.sidebar.title("Get started")
st.sidebar.markdown("**Book a 2‑week pilot (£700)**")
st.sidebar.write(f"[Email us](mailto:{CONTACT_EMAIL}?subject=Vantum%20Pilot)")
show_disclaimer = st.sidebar.checkbox("Show disclaimer", value=True, key="show_disclaimer")
st.sidebar.divider()

has_covalent = bool(COVALENT_KEY)
has_scan = any(d.get("key") for d in CHAIN_SCANS.values())
default_live = bool((has_covalent or has_scan) and ADDRESSES)
st.sidebar.title("Live data")
use_live = st.sidebar.checkbox("Use live on‑chain data", value=default_live)
lookback_hours = st.sidebar.slider("Lookback (hours)", 2, 48, 24)
abs_30m_usd = st.sidebar.number_input("30m spike threshold (USD)", min_value=1000, value=100000, step=5000)
abs_24h_usd = st.sidebar.number_input("24h spike threshold (USD)", min_value=10000, value=500000, step=10000)

if use_live:
    if has_scan:
        st.sidebar.success("Data source: Block explorers (BaseScan/Arbiscan)")
    elif has_covalent:
        st.sidebar.success("Data source: Covalent")
    else:
        st.sidebar.warning("No API keys found. Add Covalent or BaseScan/Arbiscan keys in Secrets.")

# Alerts setup
st.sidebar.title("Alerts")
dest = "Slack" if SLACK_WEBHOOK else ("Zapier" if ZAPIER_WEBHOOK else ("Discord" if DISCORD_WEBHOOK else "None"))
st.sidebar.caption(f"Destination: {dest}")
auto_post = st.sidebar.checkbox("Auto-post spikes", value=False, key="auto_post")
st.sidebar.caption("Tip: add SLACK_WEBHOOK or ZAPIER_WEBHOOK to Secrets to enable posting.")

with st.sidebar.expander("Debug"):
    st.write("use_live:", use_live)
    st.write("has_scan:", has_scan, "has_covalent:", has_covalent)
    st.write("chains:", CHAINS)
    st.write("#addresses:", len(ADDRESSES))

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

@st.cache_data(ttl=600, show_spinner=False)
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

@st.cache_data(ttl=600, show_spinner=False)
def get_token_prices(chain: str, contracts: list[str]) -> dict:
    """
    Returns {contract_address_lower: usd_price}
    """
    platform = COINGECKO_PLATFORMS.get(chain)
    if not platform or not contracts:
        return {}
    try:
        url = f"https://api.coingecko.com/api/v3/simple/token_price/{platform}"
        r = requests.get(url, params={"contract_addresses": ",".join(contracts), "vs_currencies": "usd"}, timeout=15)
        r.raise_for_status()
        data = r.json() or {}
        out = {}
        for caddr, vals in data.items():
            out[caddr.lower()] = float(vals.get("usd", 0) or 0)
        return out
    except Exception:
        return {}

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

def build_flows_covalent(chain: str, addrs, hours_back: int) -> pd.DataFrame:
    all_rows = []
    for addr in addrs:
        rows = fetch_covalent_tx(chain, addr, page_size=200)
        for r in rows:
            r["chain"] = chain
        all_rows.extend(rows)
    df = normalize_tx(all_rows)
    if df.empty:
        return df
    cutoff = pd.Timestamp.now(tz="UTC") - timedelta(hours=hours_back)
    df = df[df["ts"] >= cutoff].copy()

    addrs_set = set(a.lower() for a in addrs)
    df_in = df[df["to_addr"].isin(addrs_set)].copy()
    df_in["dir"] = "in"
    df_in["entity"] = df_in["from_addr"]

    df_out = df[df["from_addr"].isin(addrs_set)].copy()
    df_out["dir"] = "out"
    df_out["entity"] = df_out["to_addr"]

    return pd.concat([df_in, df_out], ignore_index=True)

def build_flows_scan(chain: str, addrs, hours_back: int) -> pd.DataFrame:
    eth_usd = get_eth_usd()
    if eth_usd <= 0:
        eth_usd = 3000.0  # fallback

    # Include project token pricing (AERO on Base)
    wl_contracts = list(WHITELIST_TOKENS.get(chain, {}).keys())
    wl_prices = get_token_prices(chain, wl_contracts) if wl_contracts else {}

    rows = []
    addrs_set = set(a.lower() for a in addrs)
    cutoff = pd.Timestamp.now(tz="UTC") - timedelta(hours=hours_back)

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

        # Token transfers: include stables, WETH/ETH, and whitelisted tokens (e.g., AERO)
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

            contract = str(t.get("contractAddress", "")).lower()

            if token_symbol in STABLE_TOKENS:
                amount_usd = value
            elif token_symbol in {"WETH", "ETH"}:
                amount_usd = value * eth_usd
            elif contract in wl_prices and wl_prices[contract] > 0:
                amount_usd = value * wl_prices[contract]
            else:
                # Skip other tokens to avoid noisy USD estimates
                continue

            tx_hash = t.get("hash", "")
            from_addr = (t.get("from", "") or "").lower()
            to_addr = (t.get("to", "") or "").lower()
            rows.append({"ts": ts, "tx_hash": tx_hash, "from_addr": from_addr, "to_addr": to_addr,
                         "amount_usd": amount_usd, "chain": chain})

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
    """
    Detect spikes and attach an evidence_url to a representative transaction per (chain, entity, dir) group.
    """
    if flows.empty:
        return pd.DataFrame()
    cutoff = pd.Timestamp.now(tz="UTC") - timedelta(minutes=window_minutes)
    f = flows[flows["ts"] >= cutoff].copy()
    if f.empty:
        return pd.DataFrame()
    g = f.groupby(["chain","entity","dir"], dropna=False)["amount_usd"].sum().reset_index()
    g = g[g["amount_usd"] >= abs_threshold].copy()
    if g.empty:
        return pd.DataFrame()

    # Pick a representative tx per group (max amount_usd)
    evidence_urls = []
    for _, row in g.iterrows():
        chain = row["chain"]
        entity = row["entity"]
        direction = row["dir"]
        sub = f[(f["chain"] == chain) & (f["entity"] == entity) & (f["dir"] == direction)]
        if not sub.empty:
            idx = sub["amount_usd"].astype(float).idxmax()
            txh = str(sub.loc[idx, "tx_hash"]) if "tx_hash" in sub.columns else ""
            base = SCAN_TX_BASE.get(chain, "")
            evidence_urls.append(f"{base}{txh}" if base and txh else "")
        else:
            evidence_urls.append("")
    g["evidence_url"] = evidence_urls

    g["window"] = f"{window_minutes}m" if window_minutes < 120 else "24h"
    g["ts"] = pd.Timestamp.now(tz="UTC")
    g["p95_baseline"] = None
    g["zscore"] = None
    return g[["ts","chain","entity","dir","window","amount_usd","p95_baseline","zscore","evidence_url"]]

@st.cache_data(ttl=300, show_spinner=False)
def search_urlscan(terms, limit: int = 25) -> pd.DataFrame:
    if not terms:
        return pd.DataFrame()
    results = []
    headers = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    for term in terms[:5]:
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
    now = pd.Timestamp.now(tz="UTC")
    for df, window in [(spikes_30m, "30m"), (spikes_24h, "24h")]:
        if df is None or df.empty:
            continue
        for _, r in df.iterrows():
            severity = "Critical" if r["amount_usd"] >= (abs_24h_usd if window=="24h" else abs_30m_usd) else "Warning"
            confidence = 0.8 if severity == "Critical" else 0.7
            subject = ("Inflow spike" if r["dir"] == "in" else "Outflow spike") + f" — {str(r['entity'])[:10]}… on {r['chain']}"
            rows.append({
                "ts": now,
                "severity": severity,
                "rule": "inflow_spike" if r["dir"]=="in" else "outflow_spike",
                "subject": subject,
                "confidence": confidence,
                "evidence_url": r.get("evidence_url", ""),
                "meta": json.dumps({"entity": r["entity"], "amount_usd": float(r["amount_usd"]), "window": window, "chain": r["chain"], "dir": r["dir"]})
            })
    return pd.DataFrame(rows)

# ---------- Posting helpers ----------
def _safe_post_json(url: str, payload: dict):
    try:
        r = requests.post(url, json=payload, timeout=15)
        return r.status_code, (r.text or "")[:200]
    except Exception as e:
        return None, str(e)

def post_slack(text: str):
    if not SLACK_WEBHOOK:
        return False, "No Slack webhook in Secrets"
    code, msg = _safe_post_json(SLACK_WEBHOOK, {"text": text})
    return bool(code and 200 <= code < 300), msg

def post_discord(text: str):
    if not DISCORD_WEBHOOK:
        return False, "No Discord webhook in Secrets"
    code, msg = _safe_post_json(DISCORD_WEBHOOK, {"content": text})
    return bool(code and 200 <= code < 300), msg

def post_zapier(payload: dict):
    if not ZAPIER_WEBHOOK:
        return False, "No Zapier webhook in Secrets"
    code, msg = _safe_post_json(ZAPIER_WEBHOOK, payload)
    return bool(code and 200 <= code < 300), msg

def format_alert_text(row: dict) -> str:
    sev = row.get("severity", "Warning")
    rule = row.get("rule", "")
    subject = row.get("subject", "")
    meta = row.get("meta", "{}")
    try:
        meta_obj = json.loads(meta) if isinstance(meta, str) else (meta or {})
    except Exception:
        meta_obj = {}
    chain = meta_obj.get("chain", "")
    direction = meta_obj.get("dir", "")
    window = meta_obj.get("window", "")
    amount = meta_obj.get("amount_usd", 0)
    entity = meta_obj.get("entity", "")
    eurl = row.get("evidence_url", "")

    prefix = ":rotating_light:" if sev.lower() == "critical" else ":warning:"
    line1 = f"{prefix} {sev} {rule.replace('_',' ')} on {chain} ({window}) — ${amount:,.0f}"
    line2 = f"Subject: {subject}"
    line3 = f"Direction: {direction or '?'} | Entity: {entity or '?'}"
    line4 = f"Evidence: {eurl}" if eurl else ""
    return "\n".join([x for x in [line1, line2, line3, line4] if x])

def send_alerts_df(alerts_df: pd.DataFrame) -> int:
    if alerts_df is None or alerts_df.empty:
        return 0
    posted = 0
    for _, r in alerts_df.iterrows():
        row = r.to_dict()
        text = format_alert_text(row)
        # Unified payload for Zapier mapping
        try:
            meta_obj = json.loads(row.get("meta", "{}"))
        except Exception:
            meta_obj = {}
        zap_payload = {
            "channel": "#vantum-alerts",
            "severity": row.get("severity"),
            "rule": row.get("rule"),
            "subject": row.get("subject"),
            "chain": meta_obj.get("chain"),
            "direction": meta_obj.get("dir"),
            "window": meta_obj.get("window"),
            "amount_usd": float(meta_obj.get("amount_usd", 0) or 0),
            "entity": meta_obj.get("entity"),
            "evidence_url": row.get("evidence_url"),
            "ts": str(row.get("ts", pd.Timestamp.now(tz="UTC")))
        }
        ok = False
        if SLACK_WEBHOOK:
            ok, _ = post_slack(text)
        elif ZAPIER_WEBHOOK:
            ok, _ = post_zapier(zap_payload)
        elif DISCORD_WEBHOOK:
            ok, _ = post_discord(text)
        else:
            st.warning("No Slack, Zapier, or Discord webhook configured. Add one in Secrets.")
            break
        posted += 1 if ok else 0
    return posted

# ---------- Data sourcing ----------
flows_recent = pd.DataFrame()
if use_live and ADDRESSES and (has_covalent or has_scan):
    flows_all = []
    for ch in CHAINS:
        # Prefer block explorers (better token transfer coverage); fall back to Covalent
        if has_scan:
            flows = build_flows_scan(ch, ADDRESSES, lookback_hours)
        elif has_covalent:
            flows = build_flows_covalent(ch, ADDRESSES, lookback_hours)
        else:
            flows = pd.DataFrame()
        if not flows.empty:
            flows_all.append(flows)
    flows_recent = pd.concat(flows_all, ignore_index=True) if flows_all else pd.DataFrame()

    # Spike detection computed from recent flows
    fs_30 = detect_spikes(flows_recent, window_minutes=30, abs_threshold=abs_30m_usd)
    fs_24 = detect_spikes(flows_recent, window_minutes=24*60, abs_threshold=abs_24h_usd)
    flow_spikes = pd.concat([fs_30, fs_24], ignore_index=True) if (fs_30 is not None or fs_24 is not None) else pd.DataFrame()

    brand_terms = BRAND_TERMS
    domains = search_urlscan(brand_terms)

    clusters = pd.DataFrame(columns=["cluster_id","chain","size","shared_funder","confidence","first_seen","last_seen","features"])
    alerts = build_alerts_from_spikes(fs_30, fs_24)

    # Auto-post if enabled (simple throttle to avoid spam)
    if auto_post and not alerts.empty:
        last = st.session_state.get("last_alert_post_ts")
        now_ts = pd.Timestamp.now(tz="UTC")
        if not last or (now_ts - last).total_seconds() > 120:
            n = send_alerts_df(alerts)
            if n > 0:
                st.sidebar.success(f"Posted {n} alert(s) to {dest}.")
                st.session_state["last_alert_post_ts"] = now_ts
        else:
            st.sidebar.caption("Auto-post cooling down (≤120s).")
else:
    # Demo fallback (if you don't have demo CSVs locally, these will be empty)
    flow_spikes = load_csv("data/flow_spikes.csv")
    clusters = load_csv("data/clusters.csv")
    domains = load_csv("data/domains.csv")
    alerts = load_csv("data/alerts.csv")

# ---------- Filters ----------
st.sidebar.title("Filters")
default_chains = ["base", "arbitrum"]
chains_set = set()
if isinstance(flow_spikes, pd.DataFrame) and "chain" in flow_spikes.columns:
    chains_set.update(flow_spikes["chain"].dropna().astype(str).str.lower().unique().tolist())
if isinstance(clusters, pd.DataFrame) and "chain" in clusters.columns:
    chains_set.update(clusters["chain"].dropna().astype(str).str.lower().unique().tolist())
if isinstance(flows_recent, pd.DataFrame) and "chain" in flows_recent.columns:
    chains_set.update(flows_recent["chain"].dropna().astype(str).str.lower().unique().tolist())
available_chains = sorted(chains_set) or default_chains
chains = st.sidebar.multiselect("Chains", available_chains, default=available_chains)

# Filtered views
fs = flow_spikes[flow_spikes["chain"].isin(chains)] if isinstance(flow_spikes, pd.DataFrame) and not flow_spikes.empty and "chain" in flow_spikes.columns else pd.DataFrame()
cl = clusters[clusters["chain"].isin(chains)] if isinstance(clusters, pd.DataFrame) and not clusters.empty and "chain" in clusters.columns else pd.DataFrame()
dm = domains.copy() if isinstance(domains, pd.DataFrame) else pd.DataFrame()
al = alerts.copy() if isinstance(alerts, pd.DataFrame) else pd.DataFrame()
fr = flows_recent[flows_recent["chain"].isin(chains)] if isinstance(flows_recent, pd.DataFrame) and not flows_recent.empty and "chain" in flows_recent.columns else pd.DataFrame()

# ---------- KPIs ----------
def num(x):
    try:
        return float(x)
    except Exception:
        return 0.0

gross_in = fr.loc[fr.get("dir", pd.Series(dtype=str)).str.lower() == "in", "amount_usd"].apply(num).sum() if "dir" in fr.columns else 0.0
gross_out = fr.loc[fr.get("dir", pd.Series(dtype=str)).str.lower() == "out", "amount_usd"].apply(num).sum() if "dir" in fr.columns else 0.0
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
    st.subheader("Top counterparties by net flow (lookback window)")
    if not fr.empty and "entity" in fr.columns:
        df = fr.copy()
        df["amount_usd"] = pd.to_numeric(df["amount_usd"], errors="coerce").fillna(0.0)
        df["in_usd"] = df.apply(lambda r: r["amount_usd"] if str(r.get("dir","")).lower()=="in" else 0.0, axis=1)
        df["out_usd"] = df.apply(lambda r: r["amount_usd"] if str(r.get("dir","")).lower()=="out" else 0.0, axis=1)
        top = df.groupby("entity", dropna=False).agg(in_usd=("in_usd","sum"),
                                                     out_usd=("out_usd","sum"))
        top["net_usd"] = top["in_usd"] - top["out_usd"]
        st.dataframe(top.sort_values("net_usd", ascending=False).round(0).head(10), use_container_width=True)
    else:
        st.info("No live flow data found for the selected chains and lookback. Try increasing Lookback to 24–48h and confirm explorer/Covalent keys in Secrets.")

with tab_flows:
    st.subheader("Recent flow spikes")
    if not fs.empty:
        show_cols = [c for c in ["ts","chain","entity","dir","window","amount_usd","p95_baseline","zscore","evidence_url"] if c in fs.columns]
        st.dataframe(fs.sort_values("ts", ascending=False)[show_cols], use_container_width=True)
    else:
        st.info("No flow spikes yet.")

    st.subheader("Recent raw flows")
    if not fr.empty:
        show_cols_rf = [c for c in ["ts","chain","dir","entity","amount_usd","tx_hash"] if c in fr.columns]
        st.dataframe(fr.sort_values("ts", ascending=False)[show_cols_rf].head(200), use_container_width=True)
    else:
        st.caption("No raw flows in this window.")

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
        st.info("No domain matches yet. Set client NAME or BRAND_TERMS_JSON in Secrets to help the search.")

with tab_alerts:
    st.subheader("Recent alerts")
    if not al.empty:
        show_cols_a = [c for c in ["ts","severity","rule","subject","confidence","evidence_url","meta"] if c in al.columns]
        st.dataframe(al.sort_values("ts", ascending=False)[show_cols_a], use_container_width=True)
    else:
        st.info("No alerts in this window.")

    # Send a manual test alert
    if st.button("Send test alert to Slack/Zapier"):
        test = pd.DataFrame([{
            "ts": pd.Timestamp.now(tz="UTC"),
            "severity": "Test",
            "rule": "test_alert",
            "subject": "Test alert from Vantum",
            "confidence": 0.99,
            "evidence_url": "",
            "meta": json.dumps({"entity": "0x0000000000000000000000000000000000000000",
                                "amount_usd": 12345,
                                "window": "test",
                                "chain": "base",
                                "dir": "in"})
        }])
        n = send_alerts_df(test)
        if n > 0:
            st.success(f"Sent {n} test alert(s) to {dest}.")
        else:
            st.warning("No destination configured. Add SLACK_WEBHOOK or ZAPIER_WEBHOOK to Secrets.")

# Footer
st.markdown("—")
cta = st.columns([3,1])[1]
with cta:
    st.subheader("Book a 2‑week pilot (£700)")
    st.write(f"Email: {CONTACT_EMAIL}")
    st.write("Includes live dashboard, alerts under 10 minutes, and a weekly 1‑page brief. If you don’t see value, don’t roll.")

if show_disclaimer:
    st.caption("Public data only. No investment advice. Sources and timestamps logged.")
