"""Rugpull risk scorer — analyze contracts for common rug patterns.

Combines on-chain data + heuristics to calculate a risk score.
"""

from web3 import Web3
from .utils import (
    get_web3, checksum, ERC20_ABI, label_address,
    print_header, print_ok, print_warn, print_fail, print_info,
)
from .honeypot import check_honeypot


def analyze_rugpull(address: str, chain: str = "eth") -> dict:
    """Analyze a token contract for rugpull risk."""
    w3 = get_web3(chain)
    addr = checksum(address)

    report = {
        "address": addr,
        "chain": chain,
        "checks": [],
        "score": 0,
        "risk_level": "UNKNOWN",
    }

    # 1. Check if contract has code
    try:
        code = w3.eth.get_code(addr)
        if code == b"" or code == b"0x":
            report["checks"].append({"name": "Contract Code", "status": "FAIL", "detail": "No contract code — not a contract"})
            report["score"] += 50
        else:
            report["checks"].append({"name": "Contract Code", "status": "OK", "detail": f"{len(code)} bytes deployed"})
    except Exception as e:
        report["checks"].append({"name": "Contract Code", "status": "INFO", "detail": f"Could not check: {str(e)[:50]}"})

    # 2. Check if owner is renounced
    try:
        contract = w3.eth.contract(address=addr, abi=ERC20_ABI)
        owner = contract.functions.owner().call()
        zero = "0x0000000000000000000000000000000000000000"
        dead = "0x000000000000000000000000000000000000dEaD"
        if owner.lower() in (zero, dead):
            report["checks"].append({"name": "Ownership", "status": "OK", "detail": "Owner renounced"})
        else:
            report["checks"].append({"name": "Ownership", "status": "WARN", "detail": f"Owner: {label_address(owner)}"})
            report["score"] += 10
    except Exception:
        report["checks"].append({"name": "Ownership", "status": "INFO", "detail": "No owner function (could be good or bad)"})

    # 3. Check total supply
    try:
        contract = w3.eth.contract(address=addr, abi=ERC20_ABI)
        total_supply = contract.functions.totalSupply().call()
        if total_supply > 0:
            report["checks"].append({"name": "Total Supply", "status": "INFO", "detail": f"{total_supply:,}"})
        else:
            report["checks"].append({"name": "Total Supply", "status": "FAIL", "detail": "Zero supply"})
            report["score"] += 20
    except Exception:
        report["checks"].append({"name": "Total Supply", "status": "INFO", "detail": "Cannot read supply"})

    # 4. Liquidity hint
    report["checks"].append({"name": "Liquidity", "status": "INFO", "detail": "Check manually on DEX Screener"})

    # 5. GoPlus data (honeypot, source code, proxy, etc.)
    try:
        goplus = check_honeypot(addr, chain)
        if "error" not in goplus:
            if goplus.get("is_honeypot"):
                report["score"] += 40
                report["checks"].append({"name": "Honeypot", "status": "FAIL", "detail": "Token is a honeypot"})
            else:
                report["checks"].append({"name": "Honeypot", "status": "OK", "detail": "Not a honeypot"})

            if not goplus.get("is_open_source"):
                report["score"] += 15
                report["checks"].append({"name": "Source Code", "status": "FAIL", "detail": "Not verified"})
            else:
                report["checks"].append({"name": "Source Code", "status": "OK", "detail": "Verified on explorer"})

            if goplus.get("is_proxy"):
                report["score"] += 5
                report["checks"].append({"name": "Proxy", "status": "WARN", "detail": "Proxy contract — logic can change"})

            if goplus.get("selfdestruct"):
                report["score"] += 15
                report["checks"].append({"name": "Self-Destruct", "status": "FAIL", "detail": "Has selfdestruct function"})

            if goplus.get("hidden_owner"):
                report["score"] += 10
                report["checks"].append({"name": "Hidden Owner", "status": "FAIL", "detail": "Hidden owner detected"})

            if goplus.get("owner_can_mint"):
                report["score"] += 10
                report["checks"].append({"name": "Mintable", "status": "WARN", "detail": "Owner can mint new tokens"})

            holder_count = goplus.get("holder_count", 0)
            if holder_count:
                report["checks"].append({"name": "Holders", "status": "INFO", "detail": f"{holder_count:,} holders"})
        else:
            report["checks"].append({"name": "GoPlus", "status": "INFO", "detail": f"API error: {goplus['error'][:50]}"})
    except Exception as e:
        report["checks"].append({"name": "GoPlus", "status": "INFO", "detail": f"Could not check: {str(e)[:50]}"})

    # Cap score at 100
    report["score"] = min(report["score"], 100)

    # Risk level
    if report["score"] <= 20:
        report["risk_level"] = "LOW"
    elif report["score"] <= 50:
        report["risk_level"] = "MEDIUM"
    elif report["score"] <= 75:
        report["risk_level"] = "HIGH"
    else:
        report["risk_level"] = "CRITICAL"

    return report


def print_rugpull_report(report: dict):
    """Pretty-print rugpull analysis."""
    print_header(f"RUGPULL SCORE — {report['address'][:6]}...{report['address'][-4:]}")

    for check in report["checks"]:
        status = check["status"]
        name = check["name"]
        detail = check["detail"]
        if status == "OK":
            print_ok(f"{name}: {detail}")
        elif status == "WARN":
            print_warn(f"{name}: {detail}")
        elif status == "FAIL":
            print_fail(f"{name}: {detail}")
        else:
            print_info(f"{name}: {detail}")

    print()
    score = report["score"]
    level = report["risk_level"]
    if level == "LOW":
        print_ok(f"Risk Score: {score}/100 — {level} RISK")
    elif level == "MEDIUM":
        print_warn(f"Risk Score: {score}/100 — {level} RISK")
    else:
        print_fail(f"Risk Score: {score}/100 — {level} RISK")
