"""PRNG fingerprinting for STAGE 1 - DETECT.

The strongest possible "is this MT19937?" test is not a statistical signature —
it is to *attempt the attack on a holdout*: untemper, recover state, and check
that the recovered generator predicts values that were held back.  A match is
proof, not a heuristic.  We also carry cheaper structural heuristics for LCGs.
"""

from __future__ import annotations

from ..model import PRNGType
from ..exploit.mt19937 import MT19937Cracker, N
from ..exploit import lcg


def fingerprint_mt19937(values: list[int], width: int) -> dict:
    """Try to recover MT19937 from getrandbits(32) outputs and verify on holdout."""
    if width != 32 or len(values) < N + 8:
        return {"match": False, "reason": "need >=632 32-bit words for the holdout test"}
    holdout = min(16, len(values) - N)
    feed = values[: len(values) - holdout]
    tail = values[len(values) - holdout :]
    cr = MT19937Cracker(call="getrandbits", nbits=32)
    cr.feed(feed)
    if not cr.recover():
        return {"match": False, "reason": "insufficient samples"}
    predicted = cr.predict(holdout)
    match = predicted == tail
    return {
        "match": match,
        "holdout": holdout,
        "verified": match,
        "reason": "recovered state predicts held-out outputs" if match else "no match",
    }


def fingerprint_lcg(values: list[int], width: int) -> dict:
    """Attempt a generic full-output LCG recovery from consecutive values."""
    if len(values) < 8:
        return {"match": False}
    params = lcg.recover_lcg(values[:16])
    if params is None:
        return {"match": False}
    # verify on the remainder
    ok = all(params.next(values[i]) == values[i + 1] % params.modulus
             for i in range(len(values) - 1))
    return {
        "match": ok,
        "modulus": params.modulus,
        "multiplier": params.multiplier,
        "increment": params.increment,
    }


def fingerprint_xorshift(values: list[int], width: int) -> dict:
    """Cheap structural heuristic for xorshift-family low-bit behaviour.

    Not a proof; flags a *candidate* when the low bit fails a simple linear
    predictability check that xorshift outputs tend to fail.
    """
    if len(values) < 64:
        return {"match": False, "candidate": False}
    low = [v & 1 for v in values]
    # xorshift low bits are a pure LFSR: highly linearly predictable. Rough proxy:
    matches = sum(1 for i in range(2, len(low)) if low[i] == (low[i - 1] ^ low[i - 2]))
    frac = matches / (len(low) - 2)
    return {"match": False, "candidate": frac > 0.9, "low_bit_lfsr_fraction": frac}


def fingerprint(values: list[int], width: int) -> tuple[PRNGType, float, dict]:
    """Return ``(suspected_type, confidence, evidence)``."""
    evidence: dict = {}

    mt = fingerprint_mt19937(values, width)
    evidence["mt19937"] = mt
    if mt.get("match"):
        return PRNGType.MT19937, 0.99, evidence

    lcg_fp = fingerprint_lcg(values, width)
    evidence["lcg"] = lcg_fp
    if lcg_fp.get("match"):
        return PRNGType.LCG_GENERIC, 0.95, evidence

    xs = fingerprint_xorshift(values, width)
    evidence["xorshift"] = xs
    if xs.get("candidate"):
        return PRNGType.XORSHIFT, 0.4, evidence

    return PRNGType.UNKNOWN, 0.0, evidence
