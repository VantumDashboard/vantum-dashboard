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

# Optional: dashboard link to include in alert messages
DASHBOARD_URL = SECRETS.get("app", {}).get("DASHBOARD_URL", "")

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

# Optional address page links for evidence fallback
SCAN_ADDR_BASE = {
    "base": "https://basescan.org/address/",
    "arbitrum": "https://arbiscan.io/address/",
    "ethereum": "https://etherscan.io/address/",
    "polygon": "https://polygonscan.com/address/",
    "optimism": "https://optimistic.etherscan.io/address/",
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
cooldown_min = st.sidebar.slider("Alert cooldown (minutes)", 15, 120, 60)
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

    out = pd.concat([df_in, df_out], ignore_index=True)
    # De-duplicate likely repeats across multiple addresses
    out = (out.sort_values("ts", ascending=False)
              .drop_duplicates(subset=["tx_hash","from_addr","to_addr","amount_usd","chain"], keep="first")
              .reset_index(drop=True))
    return out

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
                value = int(raw) /
