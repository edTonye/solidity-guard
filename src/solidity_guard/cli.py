import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import scan
from .models import ScanResult, Status
from .report import to_json_results, to_text

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FAIL_ON_CHOICES = tuple(SEVERITY_ORDER.keys())
OK_STATUSES = (Status.COMPLETED_NO_FINDINGS, Status.COMPLETED_WITH_FINDINGS)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="solidity-guard",
        description="Static analysis for selected Solidity security patterns.",
    )
    parser.add_argument("path", help="Path to a .sol file or a directory")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default=None,
        metavar="SEVERITY",
        help=(
            "Exit with code 1 if any finding at or above this severity is "
            f"reported. Choices: {', '.join(FAIL_ON_CHOICES)}."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"solidity-guard {__version__}",
    )
    return parser


def _collect_sol_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.sol") if p.is_file())


def _read_source(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeDecodeError as e:
        return None, f"file is not valid UTF-8: {e}"
    except OSError as e:
        return None, f"cannot read file: {e}"


def _failed_result(message: str) -> ScanResult:
    return ScanResult(
        status=Status.FAILED_INTERNAL,
        findings=[],
        scanner_version=__version__,
        error=message,
    )


def _compute_exit_code(
    results: list[tuple[str, ScanResult]], fail_on: str | None
) -> int:
    if any(r.status not in OK_STATUSES for _, r in results):
        return 3
    if fail_on is not None:
        threshold = SEVERITY_ORDER[fail_on]
        for _, r in results:
            for f in r.findings:
                if SEVERITY_ORDER[f.severity.value] <= threshold:
                    return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = Path(args.path)

    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    files = _collect_sol_files(root)
    if not files:
        print(f"error: no .sol files found under {root}", file=sys.stderr)
        return 2

    results: list[tuple[str, ScanResult]] = []
    for path in files:
        source, error = _read_source(path)
        if error is not None:
            results.append((str(path), _failed_result(error)))
            continue
        results.append((str(path), scan(source)))

    if args.format == "json":
        print(to_json_results(results))
    else:
        for path, result in results:
            print(to_text(result, path))
            print()

    return _compute_exit_code(results, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
