"""Seed-pattern heuristics for STAGE 1 - DETECT.

Flags streams that look like they came from a small or time-based seed — the
kind of mistake (``random.seed(int(time.time()))``) that makes a generator
brute-forceable regardless of family.
"""

from __future__ import annotations

import time

from ..exploit import seed_recovery


def check_time_seed(
    values: list[int],
    call: str = "getrandbits",
    nbits: int = 32,
    window_s: int = 3600,
    center: float | None = None,
) -> dict:
    """Attempt to recover a Unix-time seed in a plausible window around now."""
    if len(values) < 4:
        return {"flagged": False, "reason": "need >=4 samples"}
    res = seed_recovery.recover_time_seed(
        values, center=center, window_s=window_s, call=call, nbits=nbits, check=4
    )
    if res:
        return {"flagged": True, "seed": res.seed, "as_time": _fmt(res.seed),
                "method": res.method}
    return {"flagged": False, "window_s": window_s}


def check_small_seed(
    values: list[int],
    call: str = "getrandbits",
    nbits: int = 32,
    limit: int = 1 << 16,
) -> dict:
    """Attempt to recover a small integer seed in ``[0, limit)``."""
    if len(values) < 4:
        return {"flagged": False}
    res = seed_recovery.recover_int_seed(
        values, 0, limit, call=call, nbits=nbits, check=4
    )
    if res:
        return {"flagged": True, "seed": res.seed, "method": res.method}
    return {"flagged": False, "searched": limit}


def _fmt(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
    except (ValueError, OverflowError, OSError):
        return str(ts)
