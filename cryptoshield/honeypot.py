"""Honeypot checker — detect scam tokens before you buy.

Uses GoPlus Security API (free, no key required).
"""

from .db import cache_get, cache_set
from .utils import fetch_json, print_header, print_ok, print_warn, print_fail, print_info

GOPLUS_TOKEN_SECURITY = "https://api.gopluslabs.io/api/v1/token_security/{chain_id}"


def get_chain_id_goplus(chain: str) -> int:
    """Map chain name to GoPlus chain ID."""
    mapping = {
        "eth": 1,
        "bsc": 56,
        "polygon": 137,
        "arbitrum": 42161,
        "optimism": 10,
        "base": 8453,
        "avalanche": 43114,
        "fantom": 250,
    }
    return mapping.get(chain, 1)


def check_honeypot(address: str, chain: str = "eth") -> dict:
    """Check if a token is a honeypot using GoPlus API."""
    cache_key = f"honeypot:{chain}:{address.lower()}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    chain_id = get_chain_id_goplus(chain)
    url = GOPLUS_TOKEN_SECURITY.format(chain_id=chain_id)
    data = fetch_json(url, params={"contract_addresses": address})

    if "error" in data:
        return {"error": data["error"]}

    result = data.get("result", {})
    token_data = result.get(address.lower(), result.get(address, {}))

    if not token_data:
        return {"error": "Token not found on GoPlus"}

    # Parse into structured report
    report = {
        "address": address,
        "chain": chain,
        "token_name": token_data.get("token_name", "Unknown"),
        "token_symbol": token_data.get("token_symbol", "?"),
        "is_honeypot": _to_bool(token_data.get("is_honeypot")),
        "buy_tax": _to_float(token_data.get("buy_tax", "0")),
        "sell_tax": _to_float(token_data.get("sell_tax", "0")),
        "can_buy": not _to_bool(token_data.get("cannot_buy")),
        "can_sell": not _to_bool(token_data.get("cannot_sell_all")),
        "owner_can_mint": _to_bool(token_data.get("is_mintable")),
        "owner_can_change_balance": _to_bool(token_data.get("owner_change_balance")),
        "hidden_owner": _to_bool(token_data.get("hidden_owner")),
        "selfdestruct": _to_bool(token_data.get("selfdestruct")),
        "external_call": _to_bool(token_data.get("external_call")),
        "is_proxy": _to_bool(token_data.get("is_proxy")),
        "is_blacklisted": _to_bool(token_data.get("is_blacklisted")),
        "is_whitelisted": _to_bool(token_data.get("is_whitelisted")),
        "trading_cooldown": _to_bool(token_data.get("trading_cooldown")),
        "is_open_source": _to_bool(token_data.get("is_open_source")),
        "holder_count": _to_int(token_data.get("holder_count")),
        "total_supply": token_data.get("total_supply", "0"),
        "lp_total_supply": token_data.get("lp_total_supply", "0"),
        "lp_holder_count": _to_int(token_data.get("lp_holder_count")),
        "owner_address": token_data.get("owner_address", ""),
        "creator_address": token_data.get("creator_address", ""),
        "dex": token_data.get("dex", []),
        "risks": [],
    }

    # Calculate risk flags
    if report["is_honeypot"]:
        report["risks"].append("HONEYPOT — cannot sell")
    if report["buy_tax"] > 0.10:
        report["risks"].append(f"HIGH BUY TAX — {report['buy_tax']*100:.0f}%")
    elif report["buy_tax"] > 0.05:
        report["risks"].append(f"BUY TAX — {report['buy_tax']*100:.0f}%")
    if report["sell_tax"] > 0.10:
        report["risks"].append(f"HIGH SELL TAX — {report['sell_tax']*100:.0f}%")
    elif report["sell_tax"] > 0.05:
        report["risks"].append(f"SELL TAX — {report['sell_tax']*100:.0f}%")
    if report["owner_can_mint"]:
        report["risks"].append("OWNER CAN MINT — infinite supply risk")
    if report["owner_can_change_balance"]:
        report["risks"].append("OWNER CAN CHANGE BALANCES")
    if report["hidden_owner"]:
        report["risks"].append("HIDDEN OWNER")
    if report["selfdestruct"]:
        report["risks"].append("SELF-DESTRUCT FUNCTION")
    if report["external_call"]:
        report["risks"].append("EXTERNAL CALLS — possible exploit vector")
    if report["is_proxy"]:
        report["risks"].append("PROXY CONTRACT — logic can change")
    if not report["is_open_source"]:
        report["risks"].append("CLOSED SOURCE — cannot verify code")

    # Score: 0 = safe, 10 = scam
    score = 0
    if report["is_honeypot"]:
        score += 50
    score += min(int(report["buy_tax"] * 100), 20)
    score += min(int(report["sell_tax"] * 100), 20)
    if report["owner_can_mint"]:
        score += 15
    if report["owner_can_change_balance"]:
        score += 15
    if report["hidden_owner"]:
        score += 10
    if report["selfdestruct"]:
        score += 10
    if not report["is_open_source"]:
        score += 10
    if report["is_proxy"]:
        score += 5
    report["risk_score"] = min(score, 100)

    cache_set(cache_key, report, ttl=1800)  # Cache 30 min
    return report


def print_honeypot_report(report: dict):
    """Pretty-print honeypot check results."""
    if "error" in report:
        print_fail(f"Error: {report['error']}")
        return

    print_header(f"HONEYPOT CHECK — {report['token_name']} ({report['token_symbol']})")

    # Sell ability
    if report["can_sell"]:
        print_ok("Can sell: YES")
    else:
        print_fail("Can sell: NO — HONEYPOT")

    # Taxes
    buy_pct = report["buy_tax"] * 100
    sell_pct = report["sell_tax"] * 100
    if buy_pct == 0 and sell_pct == 0:
        print_ok("Tax: 0% buy / 0% sell")
    elif buy_pct <= 5 and sell_pct <= 5:
        print_ok(f"Tax: {buy_pct:.0f}% buy / {sell_pct:.0f}% sell")
    elif buy_pct <= 10 and sell_pct <= 10:
        print_warn(f"Tax: {buy_pct:.0f}% buy / {sell_pct:.0f}% sell")
    else:
        print_fail(f"Tax: {buy_pct:.0f}% buy / {sell_pct:.0f}% sell")

    # Owner risks
    if report["owner_can_mint"]:
        print_fail("Owner can mint: YES — infinite supply risk")
    else:
        print_ok("Owner can mint: NO")

    if report["owner_can_change_balance"]:
        print_fail("Owner can change balances: YES")

    if report["hidden_owner"]:
        print_fail("Hidden owner: YES")

    if report["selfdestruct"]:
        print_fail("Self-destruct: YES")

    if not report["is_open_source"]:
        print_warn("Contract: NOT verified / closed source")
    else:
        print_ok("Contract: Verified")

    if report["is_proxy"]:
        print_warn("Proxy contract: YES — logic can be changed")

    # Holder info
    if report["holder_count"]:
        print_info(f"Holders: {report['holder_count']}")

    # Risk score
    score = report["risk_score"]
    if score <= 20:
        print_ok(f"Risk Score: {score}/100 — LOW RISK")
    elif score <= 50:
        print_warn(f"Risk Score: {score}/100 — MEDIUM RISK")
    else:
        print_fail(f"Risk Score: {score}/100 — HIGH RISK")

    # Risk flags
    if report["risks"]:
        print()
        print("  Risks:")
        for risk in report["risks"]:
            print(f"    ⚡ {risk}")


def _to_bool(val) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val in ("1", "true", "True")
    if isinstance(val, (int, float)):
        return val == 1
    return False


def _to_float(val) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0


def _to_int(val) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0
