"""CryptoShield CLI — All-in-one crypto security toolkit."""

import sys
import typer

from . import __version__

app = typer.Typer(
    name="cryptoshield",
    help="🛡 CryptoShield — All-in-one crypto security toolkit",
    add_completion=False,
)


@app.command()
def check(
    address: str = typer.Argument(..., help="Token contract address"),
    chain: str = typer.Option("eth", "-c", "--chain", help="Chain: eth, bsc, polygon, arbitrum, optimism, base, avalanche, fantom, solana"),
    quick: bool = typer.Option(False, "-q", "--quick", help="Quick check (honeypot only)"),
):
    """Full security report for a token contract."""
    if chain == "solana":
        from .solana import check_solana_token, print_solana_token_report
        print(f"\n🛡 CRYPTO SHIELD — Scanning Solana token {address[:10]}...")
        print("━" * 50)
        report = check_solana_token(address)
        print_solana_token_report(report)
        return

    from .honeypot import check_honeypot, print_honeypot_report
    from .rugpull import analyze_rugpull, print_rugpull_report

    print(f"\n🛡 CRYPTO SHIELD — Scanning {address[:10]}... on {chain}")
    print("━" * 50)

    if quick:
        report = check_honeypot(address, chain)
        print_honeypot_report(report)
    else:
        report = analyze_rugpull(address, chain)
        print_rugpull_report(report)
        print()
        hp = check_honeypot(address, chain)
        print_honeypot_report(hp)


@app.command()
def approvals(
    wallet: str = typer.Argument(..., help="Wallet address to scan"),
    chain: str = typer.Option("eth", "-c", "--chain", help="Chain to scan"),
    blocks: int = typer.Option(100000, "-b", "--blocks", help="How many blocks back to scan"),
):
    """Scan token approvals for a wallet."""
    from .approvals import scan_approvals, print_approval_report

    print(f"\n🛡 Scanning approvals for {wallet[:10]}... on {chain}")
    results = scan_approvals(wallet, chain, blocks)
    print_approval_report(results, wallet)


@app.command()
def rugpull(
    address: str = typer.Argument(..., help="Token contract address"),
    chain: str = typer.Option("eth", "-c", "--chain", help="Chain"),
):
    """Analyze rugpull risk for a token."""
    if chain == "solana":
        from .solana import check_solana_token, print_solana_token_report
        report = check_solana_token(address)
        print_solana_token_report(report)
        return

    from .rugpull import analyze_rugpull, print_rugpull_report

    report = analyze_rugpull(address, chain)
    print_rugpull_report(report)


@app.command("check-url")
def check_url_cmd(
    url: str = typer.Argument(..., help="URL to check"),
):
    """Check if a URL is a known or suspected phishing site."""
    from .phishing import check_url, print_phishing_report

    report = check_url(url)
    print_phishing_report(report)


@app.command()
def solana(
    wallet: str = typer.Argument(..., help="Solana wallet address"),
):
    """Check Solana wallet — SOL balance + token holdings."""
    from .solana import check_solana_wallet

    print(f"\n🛡 Solana wallet scan — {wallet[:10]}...")
    print("━" * 50)
    report = check_solana_wallet(wallet)

    print(f"\n  💰 SOL Balance: {report['sol_balance']:.4f} SOL")
    print(f"  📦 Token accounts: {len(report['tokens'])}")

    if report["tokens"]:
        print("\n  Token Holdings:")
        for t in report["tokens"]:
            if t["balance"] > 0:
                print(f"    • {t['mint'][:8]}...{t['mint'][-4:]}: {t['balance']:,.2f}")


@app.command()
def batch(
    addresses_file: str = typer.Argument(..., help="File with addresses (one per line)"),
    chain: str = typer.Option("eth", "-c", "--chain", help="Chain"),
    mode: str = typer.Option("honeypot", "-m", "--mode", help="Mode: honeypot, approvals, rugpull"),
):
    """Batch check multiple addresses from a file."""
    from pathlib import Path

    path = Path(addresses_file)
    if not path.exists():
        print(f"File not found: {addresses_file}")
        sys.exit(1)

    addresses = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    print(f"\n🛡 Batch {mode} check — {len(addresses)} addresses on {chain}")
    print("━" * 50)

    for i, addr in enumerate(addresses, 1):
        print(f"\n[{i}/{len(addresses)}] {addr[:10]}...")
        if mode == "honeypot":
            if chain == "solana":
                from .solana import check_solana_token, print_solana_token_report
                report = check_solana_token(addr)
                print_solana_token_report(report)
            else:
                from .honeypot import check_honeypot, print_honeypot_report
                report = check_honeypot(addr, chain)
                print_honeypot_report(report)
        elif mode == "rugpull":
            if chain == "solana":
                from .solana import check_solana_token, print_solana_token_report
                report = check_solana_token(addr)
                print_solana_token_report(report)
            else:
                from .rugpull import analyze_rugpull, print_rugpull_report
                report = analyze_rugpull(addr, chain)
                print_rugpull_report(report)
        elif mode == "approvals":
            from .approvals import scan_approvals, print_approval_report
            results = scan_approvals(addr, chain)
            print_approval_report(results, addr)


@app.command()
def version():
    """Show version."""
    print(f"CryptoShield v{__version__}")


def main():
    app()


if __name__ == "__main__":
    main()
