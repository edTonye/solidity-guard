# solidity-guard

Static analysis for selected Solidity security patterns.

`solidity-guard` scans Solidity source and reports a small, defined set of
high-impact vulnerability patterns: state changes after external calls
(reentrancy pattern), `tx.origin` usage, unchecked low-level calls, and
pre-0.8 pragmas. Every finding carries a severity, a confidence level,
a source line, and a recommended fix.

> **This is not an audit and not a replacement for Slither, Aderyn, or a
> professional security review.** It detects *specific patterns* — not
> vulnerability classes. "No findings" does not mean "safe."

---

## What it detects

| Rule   | Severity | Confidence | Pattern                                                    |
|--------|----------|------------|------------------------------------------------------------|
| SG-001 | high     | medium     | State write after an external call in an unguarded external function |
| SG-002 | high     | medium     | `tx.origin` referenced anywhere in the source              |
| SG-003 | medium   | high       | Low-level call whose boolean return value is discarded     |
| SG-004 | info     | low        | `pragma solidity` targeting a version < 0.8                |

Each rule ships with a vulnerable fixture and a safe fixture under
`tests/fixtures/`, and every rule is protected by a regression test.

---

## Quick start

    git clone https://github.com/edTonye/solidity-guard.git
    cd solidity-guard
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"
    python -m solidity_guard.install_compiler
    pytest -v
    solidity-guard tests/fixtures/vulnerable/reentrancy.sol

### Example output

    tests/fixtures/vulnerable/reentrancy.sol: 1 issue(s) found

    [HIGH / medium] SG-001 - State change after external call (possible reentrancy)
      line 16:
                require(ok, "transfer failed");
                balances[msg.sender] = 0;
            }
      Function `withdraw` writes state after performing an external call.
      fix: Apply checks-effects-interactions: update state before the external call.

### Scanning a directory

    solidity-guard contracts/

### JSON output

    solidity-guard contracts/ --format json

### Using it as a CI gate

    solidity-guard contracts/ --fail-on high

Exits 1 if any finding at or above the given severity is present.

### Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | Success - analysis ran, no policy failure                      |
| 1    | Findings at or above --fail-on threshold                       |
| 2    | Usage error - bad path, no .sol files found                    |
| 3    | Analysis failure - parse error, missing compiler, unreadable file |

---

## Architecture

    source .sol
        |
        v
    parser.py --> solc AST (via py-solc-x)
        |
        v
    engine.py --> runs each Rule against the AST
        |
        v
    rules/*.py --> emit Finding objects
        |
        v
    report.py --> text or JSON output
        |
        v
    cli.py --> exit code, file iteration

Design decisions:

- **AST-based, not regex.** Rules operate on the `solc` AST, not on
  line-by-line text. This avoids false positives caused by comments,
  strings, and multiline constructs.
- **Rules are independent and side-effect free.** Adding a rule is one
  file plus a test.
- **ScanResult.status distinguishes six states** -
  completed_no_findings, completed_with_findings, failed_parse,
  failed_unsupported, failed_compiler_missing, failed_internal.
  "No findings" is never conflated with "analysis failed."
- **The compiler is never downloaded silently.** If the resolved `solc`
  version is not installed, the scan fails with failed_compiler_missing.

---

## Compiler setup

The scanner picks the `solc` version from the source pragma when it can
(for example, `pragma solidity ^0.7.0` resolves to `0.7.0`). If the
resolved version is not installed, the scan fails cleanly. Install a
specific version explicitly:

    python -c "import solcx; solcx.install_solc('0.7.0')"

Ranged pragmas (>=0.7.0 <0.9.0) are NOT resolved in v1 - the scanner
falls back to the default version.

---

## Docker

    docker build -t solidity-guard .
    docker run --rm -v "$PWD/tests/fixtures:/work" solidity-guard /work/vulnerable

The image runs as a non-root user and contains only what is needed to
scan Solidity files.

---

## Testing

    pytest -v
    pytest --cov=solidity_guard --cov-report=term-missing

34 tests cover rule detection, engine state handling, finding schema,
report rendering, determinism, and CLI behavior.

---

## Known limitations

- **Four rules only.** This is not a general-purpose security scanner.
- **No data-flow analysis.** SG-001 flags the *ordering* of a state write
  after an external call. It does not prove exploitability.
- **`tx.origin` is flagged on every reference**, including benign ones.
- **SG-003 does not detect captured-but-unused call returns.** Only
  top-level discarded calls are flagged.
- **SG-004 skips ranged pragmas** and does not check whether SafeMath is
  used. It is informational only.
- **Cross-function and read-only reentrancy are not detected.**
- **Custom reentrancy guards are not recognised.** Only modifiers whose
  name contains nonReentrant are treated as guards.

For deeper analysis, combine with `slither` or `aderyn`.

---

## Security disclaimer

`solidity-guard` is a heuristic analyzer. Findings require human review.
The absence of findings does NOT mean a contract is secure. Do not
deploy a contract on the basis of this tool alone.

---

## Related work

- [ci-cd-hardhat-automation](https://github.com/edTonye/ci-cd-hardhat-automation) - automated Hardhat smart-contract deployment via GitHub Actions
- [smartcontract-bugfix-demo](https://github.com/edTonye/smartcontract-bugfix-demo) - Solidity bug-fix case study
- [defi-dashboard](https://github.com/edTonye/defi-dashboard) - Web3 dashboard and wallet integration

`solidity-guard` extends that work by adding static analysis of Solidity
source before deployment.

---

## License

MIT. See `LICENSE`.
