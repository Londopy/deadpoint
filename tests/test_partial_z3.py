"""Z3 partial-output recovery tests.

These are the "beats randcrack" milestone (M3).  They are slower than the clean
path, so the heavier ``random()`` case is marked ``slow``.  ``getrandbits(31)``
is the cheapest reliable full-state recovery (~1300 words, a few seconds).
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


def test_partial_randint_power_of_two():
    r = random.Random(7)
    n = 1400
    obs = [r.randint(0, 1023) for _ in range(n)]   # width 1024 = 2**10, no rejection
    future = [r.randint(0, 1023) for _ in range(10)]
    cr = MT19937Cracker(call="randint", lo=0, hi=1023)
    cr.feed(obs)
    assert cr.recover()
    assert cr.verified
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
