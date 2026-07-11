# Case study: predicting web session tokens

> Illustrative authorized-assessment writeup (UC1 from the spec). Only run this
> against an application you own or are explicitly permitted to test.

## Scenario

A web app issues a session token on every login. The tokens *look* random —
32-bit hex, well distributed — and the developers assumed that was enough. The
token is generated server-side with:

```python
import random
def new_session_id():
    return f"{random.getrandbits(32):08x}"
```

`random.getrandbits` is MT19937. If an attacker can collect enough tokens (by
logging in repeatedly, or harvesting tokens leaked in logs/URLs), they can
recover the generator's state and **predict the session IDs issued to other
users** — a session-prediction / account-takeover primitive.

## Capture

Collect tokens by hitting the login endpoint repeatedly and saving the
`Set-Cookie` value each time. Save the hex tokens to `tokens.txt`, one per line:

```
a3f10b8c
7c2e9d54
...
```

For MT19937 recovered from full 32-bit words, 624 consecutive tokens are enough.
(deadpoint can sample a live endpoint for you — see `deadpoint.web.sample_endpoint`.)

## Detect

```bash
deadpoint analyze tokens.txt --fmt hex --width 32
```

```
Verdict   : WEAK
Suspected : MT19937
Confidence: 0.99
```

The fingerprinter doesn't guess from statistics — it *proves* MT19937 by
recovering state from a prefix and predicting held-out tokens.

## Exploit

```bash
deadpoint predict tokens.txt --fmt hex --width 32 --forward 5 --backward 5
```

deadpoint untempers the tokens, reconstructs the generator, and prints:

- the **next** 5 tokens the server will hand out (predict forward), and
- the 5 tokens issued **before** your capture window (rewind) — useful for
  demonstrating that already-issued sessions were also predictable.

A reported prediction is verified against a holdout, so it is proof, not a guess.

## Remediate

```bash
deadpoint harden app.py --snippet app.py
```

```python
# BEFORE (predictable)
import random
def new_session_id():
    return f"{random.getrandbits(32):08x}"

# AFTER (CSPRNG-backed, and longer)
import secrets
def new_session_id():
    return secrets.token_hex(16)   # 128-bit, unpredictable
```

Session identifiers must be unpredictable *and* long enough to resist online
guessing; `secrets.token_hex`/`token_urlsafe` give you both.

## CI gate

Bake the check into the build so a weak token source can never ship again:

```python
from deadpoint import ingest, analyze, Verdict

stream = ingest("captured_tokens.txt", fmt="hex", width=32)
if analyze(stream).verdict == Verdict.WEAK:
    raise SystemExit("session token source resolves to a non-CSPRNG")
```

## Takeaway

"Looks random" and "is unpredictable" are different properties. MT19937 gives you
the first and not the second; for anything an attacker benefits from guessing —
session IDs, reset tokens, nonces — you need a CSPRNG.
