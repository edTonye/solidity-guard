import re
from dataclasses import dataclass

import solcx
from solcx.exceptions import SolcError

DEFAULT_SOLC = "0.8.20"
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


class ParseError(Exception):
    pass


class UnsupportedSourceError(ParseError):
    pass


class CompilerNotInstalledError(ParseError):
    pass


@dataclass(frozen=True)
class ParseResult:
    ast: dict
    solc_version: str


def is_solc_installed(version: str = DEFAULT_SOLC) -> bool:
    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    return version in installed


def resolve_solc_version(source: str, default: str = DEFAULT_SOLC) -> str:
    """Pick a compiler version from the source pragma.

    Uses the first `x.y.z` found in a `pragma solidity` directive.
    Falls back to `default` if no version is found or the pragma is a
    range that does not include an exact version. Ranges are not
    resolved in v1 — see known limitations.
    """
    m = PRAGMA_RE.search(source)
    if not m:
        return default
    vm = VERSION_RE.search(m.group(1))
    if not vm:
        return default
    return f"{vm.group(1)}.{vm.group(2)}.{vm.group(3)}"


def parse(source: str, solc_version: str | None = None) -> ParseResult:
    if not source.strip():
        raise UnsupportedSourceError("empty source")
    version = solc_version or resolve_solc_version(source)
    if not is_solc_installed(version):
        raise CompilerNotInstalledError(
            f"solc {version} is not installed. Install it with:\n"
            f"  python -c \"import solcx; solcx.install_solc('{version}')\""
        )
    input_json = {
        "language": "Solidity",
        "sources": {"input.sol": {"content": source}},
        "settings": {"outputSelection": {"*": {"": ["ast"]}}},
    }
    try:
        output = solcx.compile_standard(input_json, solc_version=version)
    except SolcError as e:
        raise ParseError(str(e)) from e
    except Exception as e:
        raise ParseError(f"compilation failed: {e}") from e
    try:
        ast = output["sources"]["input.sol"]["ast"]
    except (KeyError, TypeError) as e:
        raise ParseError(f"unexpected solc output shape: {e}") from e
    return ParseResult(ast=ast, solc_version=version)
