# Usage

## Ingestion formats

`deadpoint <cmd> <input> --fmt <fmt> --width <bits> --endian <big|little>`

| fmt | input shape |
|---|---|
| `int` | newline/space-delimited decimals or `0x` hex ints |
| `hex` | hex tokens *or* one continuous hex blob (chunked to `--width`) |
| `b64` | base64 tokens, decoded to bytes then chunked |
| `bytes` | a raw binary file |

Use `-` as the input path to read from stdin. Order is preserved (state recovery
depends on consecutive samples); the ingester warns when samples look
non-consecutive or interleaved.

## CLI subcommands

| Command | Purpose |
|---|---|
| `analyze` | Detect only: verdict + suspected generator + stats summary. `--seed-checks` also brute-forces time/small seeds. |
| `recover` | Recover state/seed; report the recommended sample count and whether recovery verified. |
| `predict` | Recover then print `--forward N` future and `--backward N` prior outputs. |
| `harden` | Remediation report; `--snippet FILE` scans source for weak `random` usage and emits a patch. |
| `report` | Full pipeline → risk-rated plain-text (and `--json`) audit; `--out FILE` to save. |

Call modelling flags (`recover`, `predict`, `report`):
`--call {getrandbits,raw,random,randint,randrange}`, `--nbits K`, `--lo N`, `--hi N`.

## Minimum sample counts (rule of thumb)

| Observation | Reliable recovery |
|---|---|
| `getrandbits(32)` | 624 consecutive |
| `getrandbits(k<32)` | ≈ `19937/k + 624` words (a full cycle to pin trailing words) |
| `random()` | ≈ 1250 calls |
| `randint`/`randrange` | like `getrandbits(k)` for the bounds' bit width |

Below the threshold, `recover` still tries and reports `verified: false` rather
than silently returning a wrong state. `random()` is the heaviest Z3 case; solve
time and memory grow with sample count (spec risk R4 — solver blow-up is bounded
by a timeout).

## Library API

```python
from deadpoint import (
    ingest, analyze, harden, build_report, format_text, MT19937Cracker,
    NormalizedStream, DetectReport, ExploitReport, RemediateReport,
    PRNGType, Verdict, Risk,
)
from deadpoint.exploit import lcg, seed_recovery, call_models
from deadpoint.remediate import secure_helpers, codegen
```

Every stage takes/returns the dataclasses in `deadpoint.model`, so stages are
independently testable and usable without the CLI.

### CI gate example

```python
from deadpoint import ingest, analyze, Verdict

stream = ingest("captured_tokens.txt", fmt="hex", width=32)
if analyze(stream).verdict == Verdict.WEAK:
    raise SystemExit("token source resolves to a non-CSPRNG — failing the build")
```
