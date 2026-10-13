"""Explicit installer for the solc compiler binary.

Run once after installing the package:

    python -m solidity_guard.install_compiler

Scanning does not install compilers automatically.
"""

import sys

import solcx

from .parser import DEFAULT_SOLC


def main(version: str = DEFAULT_SOLC) -> int:
    try:
        solcx.install_solc(version)
    except Exception as e:
        print(f"error: failed to install solc {version}: {e}", file=sys.stderr)
        return 1
    print(f"installed solc {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
