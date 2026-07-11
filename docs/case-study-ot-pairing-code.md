# Case study: predictable pairing codes on an embedded/OT device

> Illustrative authorized-assessment writeup. Device details are generic; run
> this only against hardware you own or are permitted to test.

## Scenario

A field gateway generates a 4-digit "pairing code" at boot that a technician
enters on a companion app to bind the device. The vendor calls it "random." If
the code is predictable, an attacker on the same network segment can bind to the
device without physical access.

## Capture

The pairing code is emitted on the debug UART at each reboot. Power-cycling the
unit repeatedly yields a stream of codes:

```
4821
0193
7756
...
```

Each code is `random.randint(0, 9999)` on the device's Python-based firmware.
Save the captured integers to `pairing.txt` (one per line).

## Detect

```bash
deadpoint analyze pairing.txt --fmt int --width 16
```

The statistical battery alone won't flag 4-digit codes as obviously weak — they
*look* uniform. That's the point of the exploit stage: **looking random is not
being unpredictable.**

## Exploit

Model the actual call. `randint(0, 9999)` draws from MT19937; feed enough
observed codes and recover the state:

```bash
deadpoint predict pairing.txt --fmt int --width 16 \
    --call randint --lo 0 --hi 9999 --forward 5
```

deadpoint untempers/solves for the generator state, verifies the recovered state
against a holdout of observed codes, and prints the **next five pairing codes the
device will produce** — before it produces them.

## Remediate

```bash
deadpoint harden pairing.txt --snippet firmware_rng.py
```

The fix is not "add more digits" — it's the generator:

```python
# BEFORE (predictable)
import random
code = random.randint(0, 9999)

# AFTER (CSPRNG-backed)
import secrets
code = secrets.randbelow(10000)
```

For binding secrets that must resist offline guessing, prefer a longer token:
`secrets.token_hex(16)`.

## Takeaway

A generator that passes a uniformity check can still be fully predictable. The
audit chain — detect the usage, prove exploitability by predicting real future
outputs, then swap in a vetted CSPRNG — is the deliverable, not any single test.
