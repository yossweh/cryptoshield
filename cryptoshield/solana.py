"""Solana token security checker.

Uses Solana RPC + Jupiter API for token data.
"""

import requests
from .db import cache_get, cache_set
from .utils import print_header, print_ok, print_warn, print_fail, print_info

SOLANA_RPC = "https://api.mainnet-beta.solana.com"
JUPITER_TOKEN_API = "https://tokens.jup.ag/token/{mint}"
JUPITER_LIST = "https://tokens.jup.ag/strict"
BIRDEYE_TOKEN = "https://public-api.birdeye.so/defi/token_overview?address={mint}"


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
        "is_on_jupiter": False,
        "freeze_authority": None,
        "mint_authority": None,
        "is_mutable": True,
    }

    # 1. Get token metadata from Jupiter
    try:
        r = requests.get(JUPITER_TOKEN_API.format(mint=mint), timeout=10)
        if r.status_code == 200:
            data = r.json()
            report["token_name"] = data.get("name", "Unknown")
            report["token_symbol"] = data.get("symbol", "?")
            report["decimals"] = data.get("decimals", 0)
            report["is_on_jupiter"] = True
            report["daily_volume"] = data.get("daily_volume", 0)
    except Exception:
        pass

    # 2. Check if on Jupiter strict list (vetted tokens)
    try:
        r = requests.get(JUPITER_LIST, timeout=10)
        if r.status_code == 200:
            strict_tokens = {t["address"] for t in r.json()}
            report["is_on_jupiter_strict"] = mint in strict_tokens
    except Exception:
        report["is_on_jupiter_strict"] = False

    # 3. Get on-chain token info via RPC
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [mint, {"encoding": "jsonParsed"}],
        }
        r = requests.post(SOLANA_RPC, json=payload, timeout=10)
        data = r.json()
        account = data.get("result", {}).get("value", {})

        if account:
            parsed = account.get("data", {}).get("parsed", {})
            info = parsed.get("info", {})

            report["mint_authority"] = info.get("mintAuthority")
            report["freeze_authority"] = info.get("freezeAuthority")
            report["is_mutable"] = info.get("isInitialized", True)
            report["total_supply"] = int(info.get("supply", "0"))
            report["decimals"] = info.get("decimals", report["decimals"])
    except Exception:
        pass

    # 4. Get holder count from Birdeye (optional, may fail without API key)
    try:
        headers = {"X-API-KEY": "public"}
        r = requests.get(
            BIRDEYE_TOKEN.format(mint=mint),
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            birddata = r.json().get("data", {})
            report["holder_count"] = birddata.get("holder", 0)
            report["daily_volume"] = birddata.get("v24hUSD", report.get("daily_volume", 0))
            report["market_cap"] = birddata.get("mc", 0)
            report["price"] = birddata.get("price", 0)
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

    # Not on Jupiter
    if not report["is_on_jupiter"]:
        risks.append("NOT ON JUPITER — unvetted token, high risk")
        score += 15

    # Not on Jupiter strict list
    if not report.get("is_on_jupiter_strict"):
        risks.append("NOT ON JUPITER STRICT LIST — not officially vetted")
        score += 5

    # Low holder count
    if report["holder_count"] > 0 and report["holder_count"] < 100:
        risks.append(f"LOW HOLDER COUNT — only {report['holder_count']} holders")
        score += 15
    elif report["holder_count"] > 0 and report["holder_count"] < 1000:
        risks.append(f"SMALL HOLDER COUNT — {report['holder_count']} holders")
        score += 5

    # Low volume
    vol = report.get("daily_volume", 0)
    if vol > 0 and vol < 1000:
        risks.append(f"LOW VOLUME — ${vol:,.0f} in 24h")
        score += 10

    report["risk_score"] = min(score, 100)
    if score <= 20:
        report["risk_level"] = "LOW"
    elif score <= 50:
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
        r = requests.post(SOLANA_RPC, json=payload, timeout=10)
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
        r = requests.post(SOLANA_RPC, json=payload, timeout=10)
        data = r.json()
        accounts = data.get("result", {}).get("value", [])

        for acc in accounts:
            info = acc["account"]["data"]["parsed"]["info"]
            token_amount = info.get("tokenAmount", {})
            report["tokens"].append({
                "mint": info.get("mint", ""),
                "balance": token_amount.get("uiAmount", 0),
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

    # Jupiter status
    if report["is_on_jupiter"]:
        print_ok("Listed on Jupiter")
        if report.get("is_on_jupiter_strict"):
            print_ok("On Jupiter Strict List (vetted)")
        else:
            print_warn("NOT on Jupiter Strict List")
    else:
        print_fail("Not listed on Jupiter — unvetted token")

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

    # Holders
    if report["holder_count"]:
        if report["holder_count"] < 100:
            print_fail(f"Holders: {report['holder_count']:,}")
        elif report["holder_count"] < 1000:
            print_warn(f"Holders: {report['holder_count']:,}")
        else:
            print_ok(f"Holders: {report['holder_count']:,}")

    # Volume
    vol = report.get("daily_volume", 0)
    if vol:
        print_info(f"24h Volume: ${vol:,.0f}")

    # Market cap
    mc = report.get("market_cap", 0)
    if mc:
        print_info(f"Market Cap: ${mc:,.0f}")

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
