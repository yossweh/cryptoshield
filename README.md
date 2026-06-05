# 🛡 CryptoShield

**All-in-one crypto security toolkit.** Check tokens before you buy. Scan your wallet for dangerous approvals. Detect rugpulls. Block phishing sites.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- **🍯 Honeypot Detection** — Can you sell? Hidden taxes? Mint function? Check before you buy.
- **📋 Approval Scanner** — Find all token approvals on your wallet. Flag dangerous unlimited approvals.
- **🔴 Rugpull Scorer** — Analyze contracts for common rug patterns. Score 0-100.
- **🎣 Phishing Checker** — Detect scam URLs. Typosquatting, fake airdrops, wallet drainers.
- **📦 Batch Mode** — Check 100+ tokens/wallets from a file.

## Install

```bash
pip install cryptoshield
```

Or from source:

```bash
git clone https://github.com/yossweh/cryptoshield
cd cryptoshield
pip install -e .
```

## Usage

### Full security report
```bash
cryptoshield check 0x1234...abcd
cryptoshield check 0x1234...abcd --chain bsc
cryptoshield check 0x1234...abcd --quick  # honeypot only
```

### Scan wallet approvals
```bash
cryptoshield approvals 0xYourWallet
cryptoshield approvals 0xYourWallet --chain polygon
```

### Rugpull analysis
```bash
cryptoshield rugpull 0x1234...abcd
```

### Check phishing URL
```bash
cryptoshield check-url uniswap-airdrop.com
cryptoshield check-url https://app.uniswap.org
```

### Batch check
```bash
# File with one address per line
cryptoshield batch tokens.txt --mode honeypot
cryptoshield batch wallets.txt --mode approvals --chain bsc
```

## Example Output

```
🛡 CRYPTO SHIELD REPORT
━━━━━━━━━━━━━━━━━━━━━━━

🍯 HONEYPOT CHECK — SafeToken (SAFE)
  ✅ Can sell: YES
  ✅ Tax: 0% buy / 0% sell
  ✅ Owner can mint: NO
  ✅ Contract: Verified
  ℹ️  Holders: 12,847
  ✅ Risk Score: 5/100 — LOW RISK

📋 APPROVAL AUDIT — 0x47ac...8188
  ❌ USDT → UNLIMITED to 0xUnkn...abcd
         ⚡ RECOMMEND: revoke immediately
  ⚠️  WETH → unlimited to Uniswap V2 Router
         Known protocol — consider reducing allowance
  ✅ DAI → 500.00 to Uniswap V3 Router
  ℹ️  Total approvals: 3
  ❌ 1 HIGH RISK — revoke now!

🔴 RUGPULL SCORE — 0x1234...abcd
  ✅ Contract Code: 12,847 bytes deployed
  ❌ Ownership: Owner: 0xDang...er0us
  ❌ Source Code: Not verified
  ❌ Honeypot: Token is a honeypot
  ❌ Risk Score: 75/100 — HIGH RISK

🎣 PHISHING CHECK — uniswap-airdrop.com
  ℹ️  Unknown domain: uniswap-airdrop.com
  ❌ Possible typosquat of uniswap.org (similarity: 85%)
  ⚠️  Suspicious pattern: 'airdrop' in URL
  ❌ Risk Score: 55/100 — HIGH RISK — likely phishing
```

## Supported Chains

| Chain | Honeypot | Approvals | Rugpull |
|-------|----------|-----------|---------|
| Ethereum | ✅ | ✅ | ✅ |
| BSC | ✅ | ✅ | ✅ |
| Polygon | ✅ | ✅ | ✅ |
| Arbitrum | ✅ | ✅ | ✅ |
| Optimism | ✅ | ✅ | ✅ |
| Base | ✅ | ✅ | ✅ |
| Avalanche | ✅ | ✅ | ✅ |
| Fantom | ✅ | ✅ | ✅ |

## Data Sources

- **GoPlus Security API** — Honeypot detection, token security analysis (free, no key)
- **On-chain data** — Approval events, contract code, ownership (direct RPC)
- **Heuristics** — URL pattern matching, domain analysis, typosquatting detection

## Contributing

PRs welcome! Especially:

- More scam patterns / phishing databases
- Solana support
- Better rugpull heuristics
- UI improvements

## License

MIT
