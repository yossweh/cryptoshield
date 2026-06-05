"""Token approval scanner — find dangerous approvals on your wallet.

Scans on-chain Approval events to find all active token approvals.
"""

from web3 import Web3
from .utils import (
    get_web3, checksum, label_address, ERC20_ABI, APPROVAL_EVENT,
    KNOWN_ADDRESSES, print_header, print_ok, print_warn, print_fail, print_info,
)

# Common approval spender labels
SPENDER_LABELS = {
    **KNOWN_ADDRESSES,
    "0x0000000000000000000000000000000000000000": "Zero Address (burn)",
    "0x000000000000000000000000000000000000dead": "Dead Address (burn)",
}

# Approvals above this are considered "unlimited"
UNLIMITED_THRESHOLD = 2**250


def scan_approvals(wallet: str, chain: str = "eth", blocks_back: int = 100_000) -> list:
    """Scan all token approvals for a wallet."""
    w3 = get_web3(chain)
    wallet = checksum(wallet)

    current_block = w3.eth.block_number
    from_block = max(0, current_block - blocks_back)

    # Get Approval events where owner = wallet
    approval_topic = w3.keccak(
        text="Approval(address,address,uint256)"
    ).hex()

    try:
        logs = w3.eth.get_logs({
            "fromBlock": from_block,
            "toBlock": current_block,
            "topics": [
                approval_topic,
                "0x" + wallet[2:].lower().zfill(64),  # owner
            ],
        })
    except Exception as e:
        return [{"error": str(e)}]

    # Deduplicate: keep latest approval per (token, spender)
    approvals = {}
    for log in logs:
        try:
            token_addr = log["address"]
            spender = "0x" + log["topics"][2].hex()[-40:]
            spender = Web3.to_checksum_address(spender)
            value = int(log["data"].hex(), 16)

            key = (token_addr.lower(), spender.lower())
            approvals[key] = {
                "token": token_addr,
                "spender": spender,
                "value": value,
                "block": log["blockNumber"],
            }
        except Exception:
            continue

    # Filter: only keep current approvals (check on-chain allowance)
    active = []
    for (token_lower, spender_lower), info in approvals.items():
        if info["value"] == 0:
            continue

        try:
            contract = w3.eth.contract(
                address=checksum(info["token"]), abi=ERC20_ABI
            )
            current_allowance = contract.functions.allowance(
                wallet, checksum(info["spender"])
            ).call()

            if current_allowance == 0:
                continue

            # Get token info
            try:
                name = contract.functions.name().call()
            except Exception:
                name = "Unknown"
            try:
                symbol = contract.functions.symbol().call()
            except Exception:
                symbol = "?"

            is_unlimited = current_allowance >= UNLIMITED_THRESHOLD
            spender_label = SPENDER_LABELS.get(
                info["spender"].lower(), "Unknown Contract"
            )

            active.append({
                "token": info["token"],
                "token_name": name,
                "token_symbol": symbol,
                "spender": info["spender"],
                "spender_label": spender_label,
                "allowance": current_allowance,
                "is_unlimited": is_unlimited,
                "is_known": info["spender"].lower() in KNOWN_ADDRESSES,
            })
        except Exception:
            continue

    return active


def print_approval_report(approvals: list, wallet: str):
    """Pretty-print approval scan results."""
    if not approvals:
        print_ok("No active approvals found — your wallet is clean!")
        return

    if "error" in approvals[0]:
        print_fail(f"Error: {approvals[0]['error']}")
        return

    print_header(f"APPROVAL AUDIT — {wallet[:6]}...{wallet[-4:]}")

    dangerous = []
    caution = []
    safe = []

    for a in approvals:
        if a["is_unlimited"] and not a["is_known"]:
            dangerous.append(a)
        elif a["is_unlimited"] and a["is_known"]:
            caution.append(a)
        else:
            safe.append(a)

    # Dangerous first
    for a in dangerous:
        print_fail(
            f"{a['token_symbol']} → UNLIMITED to {label_address(a['spender'])}"
        )
        print(f"         ⚡ RECOMMEND: revoke immediately")

    # Caution
    for a in caution:
        print_warn(
            f"{a['token_symbol']} → unlimited to {label_address(a['spender'])}"
        )
        print(f"         Known protocol — consider reducing allowance")

    # Safe
    for a in safe:
        if a["allowance"] > 10**18:
            amount = f"{a['allowance'] / 10**18:.2f}"
        else:
            amount = str(a["allowance"])
        print_ok(
            f"{a['token_symbol']} → {amount} to {label_address(a['spender'])}"
        )

    print()
    print_info(f"Total approvals: {len(approvals)}")
    if dangerous:
        print_fail(f"{len(dangerous)} HIGH RISK — revoke now!")
    if caution:
        print_warn(f"{len(caution)} caution — review recommended")


REVOKE4_ABI = [
    {
        "inputs": [
            {"name": "token", "type": "address"},
            {"name": "spender", "type": "address"},
        ],
        "name": "revoke",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

# revoke.xyz contract
REVOKE_CONTRACT = "0x000000000000Dd366e1DA4F6c8a2b2F9e01f6F1E"
