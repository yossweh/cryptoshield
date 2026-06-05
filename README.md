# 🛡 CryptoShield

**All-in-one crypto security toolkit.** Check tokens before you buy. Scan your wallet for dangerous approvals. Detect rugpulls. Block phishing sites.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/cryptoshield.svg)](https://pypi.org/project/cryptoshield/)

## Why CryptoShield?

Every day, people lose money to:
- **Honeypot tokens** — you can buy but can't sell. Your funds are trapped.
- **Unlimited token approvals** — you gave a random contract permission to drain your wallet. Months later, they do.
- **Rugpulls** — team dumps all tokens, liquidity vanishes, price goes to zero.
- **Phishing sites** — fake airdrop pages that look like Uniswap but steal your seed phrase.

CryptoShield combines all these checks into **one CLI tool**. No API keys needed. No accounts. No BS. Just run a command and get a clear report.

```
# Before you ape into that token:
cryptoshield check 0xToken

# Before you connect your wallet to some random site:
cryptoshield check-url suspicious-site.com

# Check if your wallet has dangerous approvals:
cryptoshield approvals 0xYourWallet
```

## Features

- **🍯 Honeypot Detection** — Can you sell? Hidden taxes? Mint function? Check before you buy.
- **📋 Approval Scanner** — Find all token approvals on your wallet. Flag dangerous unlimited approvals.
- **🔴 Rugpull Scorer** — Analyze contracts for common rug patterns. Score 0-100.
- **🎣 Phishing Checker** — 60+ known scam domains. Typosquatting, fake airdrops, wallet drainers.
- **☀️ Solana Support** — Check SPL tokens, freeze/mint authority, Jupiter listing status.
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

### Full security report (EVM)
```bash
cryptoshield check 0xdAC17F958D2ee523a2206206994597C13D831ec7
cryptoshield check 0xToken --chain bsc
cryptoshield check 0xToken --quick  # honeypot only
```

### Solana token check
```bash
cryptoshield check EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v --chain solana
```

### Scan wallet approvals
```bash
cryptoshield approvals 0xYourWallet
cryptoshield approvals 0xYourWallet --chain polygon
```

### Check phishing URL
```bash
cryptoshield check-url uniswap-airdrop.com
cryptoshield check-url https://app.uniswap.org
cryptoshield check-url metamask-sync.xyz
```

### Solana wallet scan
```bash
cryptoshield solana YourSolanaWalletAddress
```

### Batch check
```bash
cryptoshield batch tokens.txt --mode honeypot
cryptoshield batch tokens.txt --mode honeypot --chain solana
cryptoshield batch wallets.txt --mode approvals --chain bsc
```

## Example Output

```
🛡 CRYPTO SHIELD REPORT
━━━━━━━━━━━━━━━━━━━━━━━

🍯 HONEYPOT CHECK — Tether USD (USDT)
  ✅ Can sell: YES
  ✅ Tax: 0% buy / 0% sell
  ❌ Owner can mint: YES — infinite supply risk
  ❌ Owner can change balances: YES
  ✅ Contract: Verified
  ℹ️  Holders: 14,585,422
  ⚠️  Risk Score: 30/100 — MEDIUM RISK

🎣 PHISHING CHECK — uniswap-airdrop.com
  🚨 KNOWN SCAM DOMAIN — DO NOT VISIT
  ❌ KNOWN SCAM DOMAIN — uniswap-airdrop.com is in scam database

☀️ SOLANA TOKEN CHECK — SafeToken (SAFE)
  ✅ Listed on Jupiter
  ✅ On Jupiter Strict List (vetted)
  ✅ Freeze Authority: None
  ✅ Mint Authority: None (fixed supply)
  ✅ Holders: 5,432
  ✅ Risk Score: 0/100 — LOW RISK

📋 APPROVAL AUDIT — 0x47ac...8188
  ❌ USDT → UNLIMITED to 0xUnkn...abcd
         ⚡ RECOMMEND: revoke immediately
  ⚠️  WETH → unlimited to Uniswap V2 Router
         Known protocol — consider reducing allowance
  ✅ DAI → 500.00 to Uniswap V3 Router
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
| Solana | ✅ | 🔜 | ✅ |

> 🔜 = Coming soon. SPL token delegation uses a different model than ERC-20 approvals.

## How It Works

| Check | Data Source | Key Needed? |
|-------|-----------|-------------|
| Honeypot | GoPlus Security API | No |
| Approvals | On-chain events (RPC) | No |
| Rugpull | GoPlus + on-chain heuristics | No |
| Phishing | Pattern matching + 60+ known domains | No |
| Solana tokens | Jupiter + Birdeye + Solana RPC | No |

Everything runs with public APIs and free RPC endpoints. No signups. No API keys. No tracking.

## Contributing

PRs welcome! Especially:

- More scam domains / phishing patterns
- More chain support (TON, Sui, Aptos)
- SPL token delegation scanner (Solana approvals)
- Better rugpull heuristics
- UI improvements

## License

MIT
