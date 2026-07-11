# deadpoint

**A purple-team RNG analysis toolkit.** Point it at a stream of "random" values
from software or an embedded/OT device and it will tell you whether that
randomness is predictable, **prove it** by recovering the generator's internal
state and predicting future *and* past outputs, then tell you exactly what the
code should have used instead.

```
DETECT  ->  EXPLOIT  ->  REMEDIATE      (blue -> red -> blue)
```

Non-cryptographic PRNGs (Mersenne Twister / MT19937, LCGs, xorshift) are still
routinely used where unpredictability actually matters: session tokens, password
reset tokens, "random" device IDs, challenge nonces, key generation on embedded
gear. These generators are built for statistical quality and speed, **not**
unpredictability — their state is fully recoverable from observed output
(CWE-338, CWE-330, CWE-337). deadpoint demonstrates that, and then points you at
the fix.

## What makes it different from `randcrack`

| Capability | `randcrack` | **deadpoint** |
|---|---|---|
| MT19937 from 624 clean `getrandbits(32)` | ✅ | ✅ |
| **Partial / truncated outputs** via an SMT (Z3) model | ❌ | ✅ `random()`, `getrandbits(k<32)`, `randint` |
| **Higher-level call modelling** (`random()`, `randint`, …) | ❌ | ✅ |
| **Backward** prediction (rewind prior outputs) | ❌ | ✅ |
| Multi-family (LCG, Java `Random`) | ❌ | ✅ |
| **Detect** + **remediate** stages, risk-rated report | ❌ | ✅ |
| Embedded/OT randomness-audit framing | ❌ | ✅ |

The Z3 partial-output solver is the headline: instead of needing 624 full
32-bit words, deadpoint builds a symbolic model of the MT19937 recurrence and
tempering and solves for the state from whatever bits each call actually reveals.

## Install

```bash
pip install deadpoint            # core (z3-solver, numpy)
pip install "deadpoint[remediate]"   # + cryptography for the secure AEAD helpers
```

## Quickstart (library)

```python
from deadpoint import ingest, analyze, MT19937Cracker, harden

stream = ingest("tokens.txt", fmt="hex", width=32)

report = analyze(stream)          # -> DetectReport
report.verdict                    # Verdict.WEAK
report.suspected                  # PRNGType.MT19937

cr = MT19937Cracker(call="getrandbits", nbits=32)
cr.feed(stream.values)
cr.recover()                      # untemper + state recovery
cr.predict(10)                    # next 10 outputs
cr.rewind(5)                      # 5 PRIOR outputs

# partial-output example: values came from random.randint(0, 999)
cr = MT19937Cracker(call="randint", lo=0, hi=999)
cr.feed(observed_ints); cr.recover(); cr.predict(3)

fixes = harden(report)            # -> RemediateReport (mappings + patches)
```

## Quickstart (CLI)

```bash
deadpoint analyze tokens.txt --fmt hex --width 32
deadpoint predict outputs.txt --call randint --lo 0 --hi 999 --forward 5
deadpoint recover tokens.txt --fmt hex
deadpoint harden app.py --snippet app.py
deadpoint report device_dump.hex --fmt hex --out audit.txt
```

`report` runs the full pipeline and prints a risk-rated, plain-text audit
(CRITICAL when state is recovered *and* predictions verify on a holdout); add
`--json` anywhere for machine-readable output.

## How recovery works

- **Clean path.** Each `getrandbits(32)` output is *untempered* back to its raw
  state word (the four tempering ops are bijections). 624 consecutive words clone
  the generator; the global output recurrence
  `W[k+624] = W[k+397] ^ twist(W[k], W[k+1])` gives exact forward prediction, and
  inverting the twist recovers prior outputs (all but the single oldest per
  block — MT discards 31 bits each twist).
- **Partial path.** A Z3 model of the recurrence + tempering is constrained by
  the bits each call exposes (`random()` → 27+26 bits from two words;
  `getrandbits(k)` → top *k* bits; `randint` → reduced to `getrandbits`), and
  solved for the initial state. Every recovery is confirmed against a **holdout**
  the solver never saw, so a reported success is a proven one.
- **Seeds.** Small integer and Unix-time seeds are recovered by bounded brute
  force and confirmed by replay.

## Additional generators (stretch)

Beyond CPython's `random`, deadpoint recovers three more real-world generators:

- **JavaScript / V8 `Math.random` (xorshift128+).** A 128-bit state recovered
  from ~4 observed doubles via a small Z3 model, then exact forward prediction.
  Handles V8's 64-value cache reversal (`xorshift.v8_unbatch`).

  ```python
  from deadpoint.exploit import xorshift
  cr = xorshift.V8Cracker(); cr.feed_and_recover(observed_doubles)
  cr.predict(5)                     # next Math.random() values
  ```

- **Java `Math.random` / `Random.nextDouble` (48-bit LCG).** Recovers the state
  from a *single* double by brute-forcing 2²² low bits, then predicts.

  ```python
  from deadpoint.exploit import lcg
  st = lcg.recover_java_from_double(observed_double)
  lcg.java_double_predict(st, 5)
  ```

- **PHP `mt_rand` (MT19937 mode).** PHP output is `temper(word) >> 1` — bit-for-bit
  CPython `getrandbits(31)` — so raw `mt_rand()` feeds straight into the Z3 solver.
  Includes a faithful engine, seed recovery, and range unscaling. (The legacy
  `MT_RAND_PHP` reload variant is intentionally out of scope.)

  ```python
  from deadpoint.exploit import php
  cr = php.recover(raw_mt_rand_outputs)   # cr.predict(n) -> future mt_rand()
  ```

## Diff-against-secrets demo

Run the *same* pipeline on a weak stream and a `secrets` stream side by side:

```bash
deadpoint demo --count 700
```

```
WEAK  — random                               | STRONG — secrets
  verdict    : WEAK                           |   verdict    : STRONG
  suspected  : MT19937                        |   suspected  : CSPRNG
  EXPLOIT    : state recovered, verified=True |   EXPLOIT    : not recoverable
```

One stream leaks its future; the other gives deadpoint nothing. That difference
is `secrets` / `os.urandom`.

## Non-goals (design rules, not footnotes)

- **N1.** deadpoint does **not** implement a new random number generator.
- **N2.** deadpoint implements **no cryptographic primitive by hand.** The
  remediation helpers *wrap* vetted libraries (`secrets`, `cryptography`'s AEAD)
  and nothing else. "Don't roll your own crypto" is enforced in code — see
  `deadpoint/remediate/secure_helpers.py`, where every function's docstring
  states which vetted library it wraps.
- The tool **breaks** weak RNGs and **recommends** vetted ones — the exact
  inverse of rolling your own.
- Precise about families: glibc `rand()` is an additive-feedback generator, not a
  simple LCG, and is out of scope; the clean LCG targets are Java `Random` and
  textbook full-output LCGs.

## Ethics / dual-use

deadpoint is an **auditing / defensive-research** tool for systems you own or are
authorized to test. Every example here is self-assessment or authorized
pentesting. Use it to prove a weakness so you can fix it — then fix it with
`secrets` / `os.urandom`.

## Development

```bash
pip install -e ".[dev]"
pytest -m "not slow"      # fast suite
pytest                    # includes the heavier Z3 random() recovery
```

Correctness is checkable against ground truth: property-based tests seed a known
`random.Random`, run recovery, and assert predictions *exactly* match the
reference generator's future and past outputs.

## License

MIT — see [LICENSE](LICENSE).
