"""Z3 partial-output recovery tests.

These are the "beats randcrack" milestone (M3).  They are slower than the clean
path, so the heavier cases are marked ``slow``.  ``getrandbits(31)`` is the
cheapest reliable full-state recovery (~1300 words, a few seconds) and stays in
the fast suite.
"""

import random

import pytest

from deadpoint.exploit import MT19937Cracker


def test_partial_getrandbits31_forward():
    r = random.Random(2024)
    n = 1500
    obs = [r.getrandbits(31) for _ in range(n)]
    future = [r.getrandbits(31) for _ in range(12)]
    cr = MT19937Cracker(call="getrandbits", nbits=31)
    cr.feed(obs)
    assert cr.recover()
    assert cr.verified
    assert cr.predict(12) == future


@pytest.mark.slow
def test_partial_randint_best_effort():
    # randint/randrange go through randbelow, which uses REJECTION SAMPLING
    # (getrandbits(width.bit_length()), rejecting draws >= width).  deadpoint
    # models the no-rejection case, so recovery is best-effort — it works when no
    # rejected draw fell in the observed window.  A large range makes rejection
    # negligible (~2**-30 here).  recover() returns True only if the holdout
    # verified, so a success is trustworthy.
    r = random.Random(7)
    n = 1700
    hi = (1 << 30) - 2  # width 2**30 - 1, k = 30
    obs = [r.randint(0, hi) for _ in range(n)]
    future = [r.randint(0, hi) for _ in range(10)]
    cr = MT19937Cracker(call="randint", lo=0, hi=hi)
    cr.feed(obs)
    assert cr.recover()
    assert cr.predict(10) == future


@pytest.mark.slow
def test_partial_random_forward():
    # random() is the heaviest Z3 case (2 words/call): recovery cost and memory
    # grow with sample count, so we stay comfortably above the uniqueness
    # threshold but within a modest word budget.
    r = random.Random(31337)
    n = 950
    obs = [r.random() for _ in range(n)]
    future = [r.random() for _ in range(10)]
    cr = MT19937Cracker(call="random")
    cr.feed(obs)
    assert cr.recover()
    assert cr.verified
    assert cr.predict(10) == future
