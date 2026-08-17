#!/usr/bin/env python3
"""Deploy Ingress to GenLayer Studionet using the active CLI account.

This script never accepts, reads, or stores a private key. The GenLayer CLI must
already have an active account configured; if that account is locked, unlock it
with the CLI before running this script.

Usage:
    python scripts/deploy_studionet.py
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "ingress.py"
PREFLIGHT = ROOT / "scripts" / "preflight.py"
STUDIONET_RPC = "https://studio.genlayer.com/api"


def run(command: list[str], *, cwd: pathlib.Path = ROOT) -> None:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> int:
    cli = shutil.which("genlayer")
    if cli is None:
        print(
            "ERROR: genlayer CLI is not installed or is not on PATH.",
            file=sys.stderr,
        )
        return 2

    if not CONTRACT.is_file():
        print(f"ERROR: contract not found: {CONTRACT}", file=sys.stderr)
        return 2

    # Cheap deterministic/source gate first. This deliberately does not invoke
    # genvm-lint, so a linter artifact/download problem cannot block deployment.
    run([sys.executable, str(PREFLIGHT)])

    # Show which configured account the CLI is about to use. No private key is
    # requested or printed by this script.
    run([cli, "account", "show"])

    # Use an explicit Studionet RPC so the script does not mutate the user's
    # saved default network.
    run(
        [
            cli,
            "deploy",
            "--contract",
            str(CONTRACT),
            "--rpc",
            STUDIONET_RPC,
        ]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
