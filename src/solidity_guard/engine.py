from . import __version__
from .models import ScanResult, Status
from .parser import (
    CompilerNotInstalledError,
    ParseError,
    UnsupportedSourceError,
    parse,
)
from .rules import ALL_RULES


def scan(source: str) -> ScanResult:
    try:
        parse_result = parse(source)
    except UnsupportedSourceError as e:
        return ScanResult(
            status=Status.FAILED_UNSUPPORTED,
            findings=[],
            scanner_version=__version__,
            error=str(e),
        )
    except CompilerNotInstalledError as e:
        return ScanResult(
            status=Status.FAILED_COMPILER_MISSING,
            findings=[],
            scanner_version=__version__,
            error=str(e),
        )
    except ParseError as e:
        return ScanResult(
            status=Status.FAILED_PARSE,
            findings=[],
            scanner_version=__version__,
            error=str(e),
        )
    except Exception as e:
        return ScanResult(
            status=Status.FAILED_INTERNAL,
            findings=[],
            scanner_version=__version__,
            error=f"unexpected error: {e}",
        )

    findings = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule.check(parse_result.ast, source))
        except Exception as e:
            return ScanResult(
                status=Status.FAILED_INTERNAL,
                findings=findings,
                scanner_version=__version__,
                error=f"rule {rule.id} failed: {e}",
            )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order[f.severity.value], f.line, f.rule_id))

    status = (
        Status.COMPLETED_WITH_FINDINGS if findings
        else Status.COMPLETED_NO_FINDINGS
    )
    return ScanResult(
        status=status,
        findings=findings,
        scanner_version=__version__,
    )
