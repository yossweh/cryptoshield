"""Phishing URL checker — detect crypto scam websites.

Checks against known scam databases and analyzes URL patterns.
"""

import re
from urllib.parse import urlparse
from .utils import fetch_json, print_header, print_ok, print_warn, print_fail, print_info

# Known legitimate domains
LEGIT_DOMAINS = {
    "uniswap.org", "app.uniswap.org",
    "aave.com", "app.aave.com",
    "opensea.io",
    "blur.io",
    "pancakeswap.finance", "pancakeswap.io",
    "sushi.com",
    "compound.finance",
    "makerdao.com",
    "lido.fi",
    "curve.fi",
    "1inch.io",
    "metamask.io",
    "phantom.app",
    "solflare.com",
    "walletconnect.com",
    "rainbow.me",
    "argent.xyz",
    "rabby.io",
    "paraswap.io",
    "dydx.exchange",
    "gmx.io",
    "arbitrum.io",
    "optimism.io",
    "base.org",
    "zksync.io",
    "starknet.io",
    "layerzero.network",
    "wormhole.com",
    "jito.network",
    "marinade.finance",
    "jup.ag",
    "raydium.io",
    "orca.so",
    "magic-eden.io",
    "tensorhq.xyz",
    "pump.fun",
    "dextools.io",
    "dexscreener.com",
    "etherscan.io",
    "bscscan.com",
    "polygonscan.com",
    "arbiscan.io",
    "basescan.org",
    "solscan.io",
    "coingecko.com",
    "coinmarketcap.com",
    "binance.com",
    "coinbase.com",
    "kraken.com",
    "okx.com",
    "bybit.com",
    "kucoin.com",
    "gate.io",
    "huobi.com",
    "poloniex.com",
    "bitfinex.com",
    "gemini.com",
    "bitstamp.net",
    "crypto.com",
    "eigenlayer.xyz",
    "stargate.finance",
    "jumper.exchange",
    "orbiter.finance",
    "rhino.fi",
    "synapseprotocol.com",
    "multichain.org",
    "celer.network",
    "debridge.finance",
    "li.fi",
    "socket.tech",
    "bungee.exchange",
    "chainlist.org",
    "revoke.cash",
    "debank.com",
    "zapper.fi",
    "zerion.io",
    "matcha.xyz",
    "slingshot.finance",
    "kwenta.io",
    "velodrome.finance",
    "aerodrome.finance",
    "camelot.exchange",
    "traderjoexyz.com",
    "spookyswap.finance",
    "spiritswap.finance",
    "beets.fi",
    "balancer.fi",
    "frax.finance",
    "convexfinance.com",
    "yearn.finance",
    "synthetix.io",
    "perp.com",
    "gains.trade",
    "mux.network",
    "aevo.xyz",
    "premia.finance",
    "lyra.finance",
    "hegic.co",
    "ribbon.finance",
    "opyn.co",
    "squeeth.com",
    "aztec.network",
    "scroll.io",
    "linea.build",
    "mantle.xyz",
    "manta.network",
    "connext.network",
    "across.to",
    "hop.exchange",
    "satellite.axelar.network",
    "squidrouter.com",
    "chainge.finance",
}

# Suspicious keywords in URLs
SCAM_PATTERNS = [
    r"airdrop",
    r"claim",
    r"free",
    r"bonus",
    r"reward",
    r"gift",
    r"presale",
    r"pre-sale",
    r"whitelist",
    r"mint-free",
    r"connect-wallet",
    r"verify",
    r"restore",
    r"sync",
    r"validate",
    r"update.*wallet",
    r"security.*alert",
    r"suspended",
    r"limited.*time",
    r"act.*now",
    r"urgent",
    r"migration",
    r"migrate",
    r"unlock",
    r"activate",
    r"confirm.*seed",
    r"seed.*phrase",
    r"private.*key",
    r"recovery",
    r"support.*chat",
    r"live.*chat",
    r"help.*desk",
    r"fix.*wallet",
    r"repair",
    r"rectify",
    r"resolve.*issue",
    r"pending.*transaction",
    r"failed.*transaction",
    r"stuck.*funds",
    r"frozen.*account",
    r"kyc.*verify",
    r"identity.*verify",
    r"document.*upload",
    r"passport",
    r"driver.*license",
    r"social.*security",
    r"tax.*refund",
    r"gas.*fee.*refund",
    r"rebate",
    r"cashback",
    r"double.*your",
    r"multiply",
    r"investment.*opportunity",
    r"guaranteed.*profit",
    r"risk.*free",
    r"passive.*income",
    r"financial.*freedom",
    r"early.*access",
    r"beta.*test",
    r"exclusive.*offer",
    r"limited.*supply",
    r"last.*chance",
    r"final.*notice",
    r"action.*required",
    r"immediate.*attention",
]

# TLDs commonly used by scammers
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".buzz", ".click", ".link",
    ".site", ".online", ".icu", ".work", ".fit", ".monster",
    ".cfd", ".sbs", ".surf", ".rest", ".cam", ".hair",
    ".mom", ".lol", ".bond", ".cyou", ".uno", ".sarl",
    ".mov", ".zip", ".py", ".sh", ".tk", ".ml", ".ga", ".cf", ".gq",
]

# Known scam domains (community-reported)
KNOWN_SCAM_DOMAINS = {
    "uniswap-airdrop.com",
    "metamask-airdrop.com",
    "metamask-sync.com",
    "metamask-restore.com",
    "metamask-verify.com",
    "metamask-update.com",
    "phantom-airdrop.com",
    "phantom-sync.com",
    "phantom-restore.com",
    "arbitrum-airdrop.com",
    "arbitrum-claim.com",
    "optimism-airdrop.com",
    "starknet-airdrop.com",
    "zksync-airdrop.com",
    "layerzero-airdrop.com",
    "eigenlayer-airdrop.com",
    "jito-airdrop.com",
    "jupiter-airdrop.com",
    "blur-airdrop.com",
    "pudgypenguins-airdrop.com",
    "apecoin-claim.com",
    "uniswapv3.com",
    "app-uniswap.org",
    "uniswap-app.org",
    "metamask-download.com",
    "metamask-extension.com",
    "metamask-io.com",
    "metamask-wallet.com",
    "pancakeswap-finance.com",
    "aave-protocol.com",
    "opensea-io.com",
    "opensea-nft.com",
    "coinbase-airdrop.com",
    "binance-airdrop.com",
    "crypto-com-airdrop.com",
}


def check_url(url: str) -> dict:
    """Analyze a URL for phishing indicators."""
    # Normalize URL
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    report = {
        "url": url,
        "domain": domain,
        "path": parsed.path,
        "is_legit": False,
        "is_suspicious": False,
        "is_known_scam": False,
        "indicators": [],
        "risk_score": 0,
    }

    # 0. Check known scam domains FIRST
    base_domain = _get_base_domain(domain)
    if domain in KNOWN_SCAM_DOMAINS or base_domain in KNOWN_SCAM_DOMAINS:
        report["is_known_scam"] = True
        report["is_suspicious"] = True
        report["indicators"].append({
            "type": "FAIL",
            "detail": f"KNOWN SCAM DOMAIN — {domain} is in scam database"
        })
        report["risk_score"] = 90
        return report

    # 1. Check if it's a known legitimate domain
    if base_domain in LEGIT_DOMAINS or domain in LEGIT_DOMAINS:
        report["is_legit"] = True
        report["indicators"].append({"type": "OK", "detail": f"Known legitimate domain: {base_domain}"})
        report["risk_score"] = 0
        return report

    report["indicators"].append({"type": "INFO", "detail": f"Unknown domain: {domain}"})
    report["risk_score"] += 10

    # 2. Check for typosquatting (similar to legit domains)
    for legit in LEGIT_DOMAINS:
        similarity = _domain_similarity(domain, legit)
        if similarity > 0.7 and similarity < 1.0:
            report["is_suspicious"] = True
            report["indicators"].append({
                "type": "FAIL",
                "detail": f"Possible typosquat of {legit} (similarity: {similarity:.0%})"
            })
            report["risk_score"] += 30

    # 3. Check for scam patterns in URL
    full_url = url.lower()
    matched_patterns = []
    for pattern in SCAM_PATTERNS:
        if re.search(pattern, full_url):
            matched_patterns.append(pattern)

    if matched_patterns:
        report["is_suspicious"] = True
        if len(matched_patterns) == 1:
            report["indicators"].append({
                "type": "WARN",
                "detail": f"Suspicious pattern: '{matched_patterns[0]}' in URL"
            })
            report["risk_score"] += 10
        else:
            report["indicators"].append({
                "type": "FAIL",
                "detail": f"Multiple suspicious patterns ({len(matched_patterns)}): {', '.join(matched_patterns[:3])}"
            })
            report["risk_score"] += 15 * len(matched_patterns)

    # 4. Check TLD
    tld = "." + domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        report["indicators"].append({
            "type": "WARN",
            "detail": f"Suspicious TLD: {tld}"
        })
        report["risk_score"] += 5

    # 5. Check for IP address instead of domain
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        report["is_suspicious"] = True
        report["indicators"].append({
            "type": "FAIL",
            "detail": "IP address used instead of domain name"
        })
        report["risk_score"] += 25

    # 6. Check for excessive subdomains
    subdomain_count = domain.count(".") - 1
    if subdomain_count > 2:
        report["is_suspicious"] = True
        report["indicators"].append({
            "type": "WARN",
            "detail": f"Excessive subdomains ({subdomain_count})"
        })
        report["risk_score"] += 10

    # 7. Check for punycode (IDN homograph attack)
    if "xn--" in domain:
        report["is_suspicious"] = True
        report["indicators"].append({
            "type": "FAIL",
            "detail": "Punycode domain — possible IDN homograph attack"
        })
        report["risk_score"] += 20

    # 8. Check domain length
    if len(domain) > 30:
        report["indicators"].append({
            "type": "WARN",
            "detail": f"Very long domain name ({len(domain)} chars)"
        })
        report["risk_score"] += 5

    # 9. Check for hyphens (common in phishing)
    if domain.count("-") > 2:
        report["indicators"].append({
            "type": "WARN",
            "detail": f"Multiple hyphens in domain ({domain.count('-')} hyphens)"
        })
        report["risk_score"] += 5

    # 10. Check for brand names in non-brand domains
    brand_domains = ["uniswap", "metamask", "phantom", "aave", "opensea", "blur",
                     "pancakeswap", "sushi", "compound", "lido", "curve", "binance",
                     "coinbase", "kraken", "okx", "bybit", "arbitrum", "optimism",
                     "zksync", "starknet", "eigenlayer", "jito", "jupiter", "raydium"]
    for brand in brand_domains:
        if brand in domain and base_domain not in LEGIT_DOMAINS:
            report["is_suspicious"] = True
            report["indicators"].append({
                "type": "FAIL",
                "detail": f"Brand name '{brand}' in non-official domain"
            })
            report["risk_score"] += 25
            break

    # Cap score
    report["risk_score"] = min(report["risk_score"], 100)

    if report["risk_score"] >= 40:
        report["is_suspicious"] = True

    return report


def print_phishing_report(report: dict):
    """Pretty-print URL check results."""
    print_header(f"PHISHING CHECK — {report['domain']}")

    if report.get("is_known_scam"):
        print_fail("🚨 KNOWN SCAM DOMAIN — DO NOT VISIT")
        for ind in report["indicators"]:
            print_fail(ind["detail"])
        return

    if report["is_legit"]:
        print_ok("Known legitimate domain")
        return

    for ind in report["indicators"]:
        if ind["type"] == "OK":
            print_ok(ind["detail"])
        elif ind["type"] == "WARN":
            print_warn(ind["detail"])
        elif ind["type"] == "FAIL":
            print_fail(ind["detail"])
        else:
            print_info(ind["detail"])

    print()
    score = report["risk_score"]
    if score <= 20:
        print_ok(f"Risk Score: {score}/100 — Likely safe")
    elif score <= 50:
        print_warn(f"Risk Score: {score}/100 — Suspicious — verify carefully")
    else:
        print_fail(f"Risk Score: {score}/100 — HIGH RISK — likely phishing")


def _get_base_domain(domain: str) -> str:
    """Extract base domain (e.g., app.uniswap.org → uniswap.org)."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _domain_similarity(a: str, b: str) -> float:
    """Simple character-level similarity between two domains."""
    a_base = _get_base_domain(a)
    b_base = _get_base_domain(b)

    if a_base == b_base:
        return 1.0

    # Levenshtein-like ratio
    longer = max(len(a_base), len(b_base))
    if longer == 0:
        return 1.0

    matches = sum(1 for x, y in zip(a_base, b_base) if x == y)
    return matches / longer
