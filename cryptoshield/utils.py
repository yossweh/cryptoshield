"""Shared utilities."""

import sys
from typing import Optional

import requests
from web3 import Web3

# Default RPC endpoints (public, no key needed) — with fallbacks
RPC_ENDPOINTS = {
    "eth": [
        "https://rpc.ankr.com/eth",
        "https://eth.llamarpc.com",
        "https://eth.drpc.org",
        "https://cloudflare-eth.com",
    ],
    "bsc": [
        "https://bsc-dataseed1.binance.org",
        "https://bsc-dataseed2.binance.org",
        "https://rpc.ankr.com/bsc",
    ],
    "polygon": [
        "https://polygon-rpc.com",
        "https://rpc.ankr.com/polygon",
        "https://polygon.drpc.org",
    ],
    "arbitrum": [
        "https://arb1.arbitrum.io/rpc",
        "https://rpc.ankr.com/arbitrum",
        "https://arbitrum.drpc.org",
    ],
    "optimism": [
        "https://mainnet.optimism.io",
        "https://rpc.ankr.com/optimism",
        "https://optimism.drpc.org",
    ],
    "base": [
        "https://mainnet.base.org",
        "https://rpc.ankr.com/base",
        "https://base.drpc.org",
    ],
    "avalanche": [
        "https://api.avax.network/ext/bc/C/rpc",
        "https://rpc.ankr.com/avalanche",
    ],
    "fantom": [
        "https://rpc.ftm.tools",
        "https://rpc.ankr.com/fantom",
    ],
}

CHAIN_IDS = {
    "eth": 1,
    "bsc": 56,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "base": 8453,
    "avalanche": 43114,
    "fantom": 250,
}

# Minimal ERC-20 ABI
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [
            {"name": "_owner", "type": "address"},
            {"name": "_spender", "type": "address"},
        ],
        "name": "allowance",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_spender", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "owner",
        "outputs": [{"name": "", "type": "address"}],
        "type": "function",
    },
]

# Known addresses to label
KNOWN_ADDRESSES = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router V4",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Router V5",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Seaport (OpenSea)",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Universal Router",
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "Seaport 1.5",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
}


def get_web3(chain: str = "eth") -> Web3:
    """Get Web3 instance with automatic RPC fallback."""
    endpoints = RPC_ENDPOINTS.get(chain)
    if not endpoints:
        print(f"Unsupported chain: {chain}")
        sys.exit(1)

    for rpc in endpoints:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
            # Test connection
            w3.eth.block_number
            return w3
        except Exception:
            continue

    print(f"All RPC endpoints failed for {chain}")
    sys.exit(1)


def is_valid_address(addr: str) -> bool:
    return Web3.is_address(addr)


def checksum(addr: str) -> str:
    return Web3.to_checksum_address(addr)


def label_address(addr: str) -> str:
    addr_lower = addr.lower()
    label = KNOWN_ADDRESSES.get(addr_lower, "")
    if label:
        return f"{addr[:6]}...{addr[-4:]} ({label})"
    return f"{addr[:6]}...{addr[-4:]}"


def fetch_json(url: str, params: Optional[dict] = None, timeout: int = 15) -> dict:
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def print_header(title: str):
    print(f"\n{'━' * 40}")
    print(f"  {title}")
    print(f"{'━' * 40}")


def print_ok(msg: str):
    print(f"  ✅ {msg}")


def print_warn(msg: str):
    print(f"  ⚠️  {msg}")


def print_fail(msg: str):
    print(f"  ❌ {msg}")


def print_info(msg: str):
    print(f"  ℹ️  {msg}")
