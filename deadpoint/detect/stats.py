"""Statistical battery for STAGE 1 - DETECT.

A *subset* of the usual randomness tests — enough to flag a stream as
non-random, not a full NIST SP 800-22 reimplementation (that is an explicit
non-goal).  Each test returns a small result dict; :func:`run_battery` bundles
them and adds a coarse ``looks_random`` verdict.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any


def _bits(values: list[int], width: int) -> list[int]:
    out: list[int] = []
    for v in values:
        for i in range(width - 1, -1, -1):
            out.append((v >> i) & 1)
    return out


def monobit(bits: list[int]) -> dict:
    n = len(bits)
    ones = sum(bits)
    s = (ones - (n - ones)) / math.sqrt(n) if n else 0.0
    p = math.erfc(abs(s) / math.sqrt(2)) if n else 1.0
    return {"ones": ones, "zeros": n - ones, "p_value": p, "pass": p >= 0.01}


def block_frequency(bits: list[int], block: int = 128) -> dict:
    n = len(bits)
    nblocks = n // block
    if nblocks == 0:
        return {"p_value": 1.0, "pass": True, "blocks": 0}
    chi = 0.0
    for i in range(nblocks):
        pi = sum(bits[i * block : (i + 1) * block]) / block
        chi += (pi - 0.5) ** 2
    chi *= 4 * block
    p = _igamc(nblocks / 2, chi / 2)
    return {"p_value": p, "pass": p >= 0.01, "blocks": nblocks}


def runs(bits: list[int]) -> dict:
    n = len(bits)
    if n < 2:
        return {"p_value": 1.0, "pass": True}
    pi = sum(bits) / n
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return {"p_value": 0.0, "pass": False, "note": "failed prerequisite frequency"}
    vobs = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(vobs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = math.erfc(num / den) if den else 0.0
    return {"runs": vobs, "p_value": p, "pass": p >= 0.01}


def serial_correlation(values: list[int]) -> dict:
    n = len(values)
    if n < 3:
        return {"correlation": 0.0, "pass": True}
    mean = sum(values) / n
    num = sum((values[i] - mean) * (values[(i + 1) % n] - mean) for i in range(n))
    den = sum((v - mean) ** 2 for v in values)
    r = num / den if den else 0.0
    return {"correlation": r, "pass": abs(r) < 3 / math.sqrt(n)}


def chi_square_uniform(values: list[int], width: int, bins: int = 256) -> dict:
    n = len(values)
    if n < bins:
        return {"p_value": 1.0, "pass": True, "note": "too few samples"}
    maxv = 1 << width
    counts = Counter(min(bins - 1, (v * bins) // maxv) for v in values)
    expected = n / bins
    chi = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(bins))
    p = _igamc((bins - 1) / 2, chi / 2)
    return {"chi_square": chi, "p_value": p, "pass": p >= 0.01}


def entropy(values: list[int], width: int) -> dict:
    """Shannon entropy per bit and a min-entropy estimate (per bit)."""
    bits = _bits(values, width)
    n = len(bits)
    if not n:
        return {"shannon_per_bit": 0.0, "min_entropy_per_bit": 0.0}
    p1 = sum(bits) / n
    shannon = 0.0
    for p in (p1, 1 - p1):
        if p > 0:
            shannon -= p * math.log2(p)
    pmax = max(p1, 1 - p1)
    min_ent = -math.log2(pmax) if pmax > 0 else 0.0
    # byte-level Shannon for a fuller picture
    byte_counts: Counter[int] = Counter()
    for v in values:
        for i in range(0, width, 8):
            byte_counts[(v >> i) & 0xFF] += 1
    total = sum(byte_counts.values())
    byte_shannon = -sum(
        (c / total) * math.log2(c / total) for c in byte_counts.values()
    ) if total else 0.0
    return {
        "shannon_per_bit": shannon,
        "min_entropy_per_bit": min_ent,
        "shannon_per_byte": byte_shannon,
    }


def run_battery(values: list[int], width: int = 32) -> dict:
    bits = _bits(values, width)
    results: dict[str, Any] = {
        "monobit": monobit(bits),
        "block_frequency": block_frequency(bits),
        "runs": runs(bits),
        "serial_correlation": serial_correlation(values),
        "chi_square_uniform": chi_square_uniform(values, width),
        "entropy": entropy(values, width),
    }
    passes = [
        results["monobit"]["pass"],
        results["block_frequency"]["pass"],
        results["runs"]["pass"],
        results["serial_correlation"]["pass"],
        results["chi_square_uniform"]["pass"],
    ]
    results["looks_random"] = all(passes)
    results["tests_passed"] = f"{sum(passes)}/{len(passes)}"
    return results


# --- lower incomplete gamma (regularized upper) for chi-square p-values ------
def _igamc(a: float, x: float) -> float:
    if x < 0 or a <= 0:
        return 1.0
    if x == 0:
        return 1.0
    if x < a + 1:
        return 1.0 - _igam(a, x)
    # continued fraction
    big = 1e300
    tiny = 1e-300
    b = x + 1 - a
    c = big
    d = 1 / b
    h = d
    for i in range(1, 300):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-12:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def _igam(a: float, x: float) -> float:
    if x <= 0:
        return 0.0
    ap = a
    s = 1 / a
    delta = s
    for _ in range(300):
        ap += 1
        delta *= x / ap
        s += delta
        if abs(delta) < abs(s) * 1e-12:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))
