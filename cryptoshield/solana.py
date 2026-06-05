"""Solana token security checker.

Uses Solana RPC + Solana Token Registry for token data.
"""

import requests
from .db import cache_get, cache_set
from .utils import print_header, print_ok, print_warn, print_fail, print_info

SOLANA_RPC = "https://api.mainnet-beta.solana.com"
TOKEN_REGISTRY_URL = "https://raw.githubusercontent.com/solana-labs/token-list/main/src/tokens/solana.tokenlist.json"

# Cache the token registry
_registry_cache = None


def _get_token_registry() -> dict:
    """Get the Solana token registry (cached)."""
    global _registry_cache
    if _registry_cache is not None:
        return _registry_cache

    cached = cache_get("solana_token_registry")
    if cached:
        _registry_cache = cached
        return cached

    try:
        r = requests.get(TOKEN_REGISTRY_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        tokens = {}
        for t in data.get("tokens", []):
            tokens[t["address"]] = t
        _registry_cache = tokens
        cache_set("solana_token_registry", tokens, ttl=86400)  # Cache 24h
        return tokens
    except Exception:
        _registry_cache = {}
        return {}


def check_solana_token(mint: str) -> dict:
    """Check a Solana SPL token for security issues."""
    cache_key = f"solana_token:{mint}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    report = {
        "mint": mint,
        "chain": "solana",
        "token_name": "Unknown",
        "token_symbol": "?",
        "risks": [],
        "risk_score": 0,
        "holder_count": 0,
        "total_supply": 0,
        "decimals": 0,
        "is_known": False,
        "freeze_authority": None,
        "mint_authority": None,
        "tags": [],
    }

    # 1. Get token info from registry
    registry = _get_token_registry()
    if mint in registry:
        token_info = registry[mint]
        report["token_name"] = token_info.get("name", "Unknown")
        report["token_symbol"] = token_info.get("symbol", "?")
        report["decimals"] = token_info.get("decimals", 0)
        report["is_known"] = True
        report["tags"] = token_info.get("tags", [])

    # 2. Get on-chain token info via RPC
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [mint, {"encoding": "jsonParsed"}],
        }
        r = requests.post(SOLANA_RPC, json=payload, timeout=15)
        data = r.json()
        account = data.get("result", {}).get("value", {})

        if account:
            parsed = account.get("data", {}).get("parsed", {})
            info = parsed.get("info", {})

            report["mint_authority"] = info.get("mintAuthority")
            report["freeze_authority"] = info.get("freezeAuthority")
            supply_raw = int(info.get("supply", "0"))
            report["total_supply"] = supply_raw
            report["decimals"] = info.get("decimals", report["decimals"])

            # Calculate human-readable supply
            if report["decimals"] > 0:
                report["total_supply_ui"] = supply_raw / (10 ** report["decimals"])
            else:
                report["total_supply_ui"] = supply_raw
    except Exception as e:
        report["rpc_error"] = str(e)[:50]

    # 3. Get holder count from Solana RPC (approximate)
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenLargestAccounts",
            "params": [mint],
        }
        r = requests.post(SOLANA_RPC, json=payload, timeout=15)
        data = r.json()
        largest = data.get("result", {}).get("value", [])
        report["top_holders"] = len(largest)
    except Exception:
        pass

    # Risk analysis
    risks = report["risks"]
    score = 0

    # Freeze authority
    if report["freeze_authority"]:
        risks.append("FREEZE AUTHORITY — issuer can freeze your tokens")
        score += 20

    # Mint authority
    if report["mint_authority"]:
        risks.append("MINT AUTHORITY — unlimited supply, issuer can mint more")
        score += 15

    # Not in registry
    if not report["is_known"]:
        risks.append("NOT IN TOKEN REGISTRY — unvetted token, high risk")
        score += 15

    # Stablecoin tag (positive)
    if "stablecoin" in report.get("tags", []):
        score -= 10  # Lower risk for known stablecoins

    # Native SOL wrapped (positive)
    if "native" in report.get("tags", []):
        score -= 5

    report["risk_score"] = max(min(score, 100), 0)
    if report["risk_score"] <= 20:
        report["risk_level"] = "LOW"
    elif report["risk_score"] <= 50:
        report["risk_level"] = "MEDIUM"
    else:
        report["risk_level"] = "HIGH"

    cache_set(cache_key, report, ttl=1800)
    return report


def check_solana_wallet(wallet: str) -> dict:
    """Check SOL balance and token holdings for a wallet."""
    report = {
        "wallet": wallet,
        "sol_balance": 0,
        "tokens": [],
    }

    # Get SOL balance
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [wallet],
        }
        r = requests.post(SOLANA_RPC, json=payload, timeout=15)
        data = r.json()
        report["sol_balance"] = data.get("result", {}).get("value", 0) / 1e9
    except Exception:
        pass

    # Get token accounts
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountsByOwner",
            "params": [
                wallet,
                {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
                {"encoding": "jsonParsed"},
            ],
        }
        r = requests.post(SOLANA_RPC, json=payload, timeout=15)
        data = r.json()
        accounts = data.get("result", {}).get("value", [])

        registry = _get_token_registry()

        for acc in accounts:
            info = acc["account"]["data"]["parsed"]["info"]
            token_amount = info.get("tokenAmount", {})
            mint = info.get("mint", "")
            balance = token_amount.get("uiAmount", 0)

            # Get token name from registry
            name = "Unknown"
            symbol = mint[:6]
            if mint in registry:
                name = registry[mint].get("name", "Unknown")
                symbol = registry[mint].get("symbol", symbol)

            report["tokens"].append({
                "mint": mint,
                "name": name,
                "symbol": symbol,
                "balance": balance,
                "decimals": token_amount.get("decimals", 0),
            })
    except Exception:
        pass

    return report


def print_solana_token_report(report: dict):
    """Pretty-print Solana token check."""
    name = report["token_name"]
    symbol = report["token_symbol"]
    print_header(f"SOLANA TOKEN CHECK — {name} ({symbol})")

    # Known status
    if report.get("is_known"):
        print_ok("Listed in Solana Token Registry")
        tags = report.get("tags", [])
        if tags:
            print_info(f"Tags: {', '.join(tags)}")
    else:
        print_warn("NOT in Token Registry — unvetted token")

    # Freeze authority
    if report["freeze_authority"]:
        print_fail(f"Freeze Authority: {report['freeze_authority'][:10]}...")
    else:
        print_ok("Freeze Authority: None")

    # Mint authority
    if report["mint_authority"]:
        print_fail(f"Mint Authority: {report['mint_authority'][:10]}...")
    else:
        print_ok("Mint Authority: None (fixed supply)")

    # Supply
    if report.get("total_supply_ui"):
        print_info(f"Total Supply: {report['total_supply_ui']:,.2f}")

    # Top holders
    if report.get("top_holders"):
        print_info(f"Top holders: {report['top_holders']} largest accounts")

    # Risk score
    score = report["risk_score"]
    level = report.get("risk_level", "UNKNOWN")
    if level == "LOW":
        print_ok(f"Risk Score: {score}/100 — {level} RISK")
    elif level == "MEDIUM":
        print_warn(f"Risk Score: {score}/100 — {level} RISK")
    else:
        print_fail(f"Risk Score: {score}/100 — {level} RISK")

    if report["risks"]:
        print()
        for risk in report["risks"]:
            print(f"    ⚡ {risk}")
