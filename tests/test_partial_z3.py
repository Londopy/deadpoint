"""Z3 partial-output recovery + exact seed-recovery tests (M3/M4).

The symbolic Z3 tests pass ``try_seed=False`` so they exercise the state solver
rather than short-circuiting on the (small) test seed.  ``getrandbits(31)`` stays
in the fast suite; heavier cases are marked ``slow``.
"""

import random

import pytest

from deadpoint.exploit import MT19937Cracker


def test_partial_getrandbits31_forward():
    r = random.Random(2024)
    n = 1500
    obs = [r.getrandbits(31) for _ in range(n)]
    future = [r.getrandbits(31) for _ in range(12)]
    cr = MT19937Cracker(call="getrandbits", nbits=31, try_seed=False)
    cr.feed(obs)
    assert cr.recover()
    assert cr.verified
    assert cr.predict(12) == future


def test_randint_rejection_handled_exactly_via_seed():
    # randint(0, 1023) -> randbelow(1024) -> getrandbits(11) with ~50% REJECTION.
    # The symbolic path is best-effort here, but a small seed is recovered exactly
    # by replaying the real generator, so rejection is handled perfectly.
    seed = 1234567
    r = random.Random(seed)
    obs = [r.randint(0, 1023) for _ in range(40)]
    future = [r.randint(0, 1023) for _ in range(10)]
    cr = MT19937Cracker(call="randint", lo=0, hi=1023, seed_int_limit=1 << 21)
    cr.feed(obs)
    assert cr.recover()
    assert cr.verified
    assert cr._seed == seed
    assert cr.predict(10) == future


def test_random_via_seed_exact():
    seed = 424242
    r = random.Random(seed)
    obs = [r.random() for _ in range(20)]
    future = [r.random() for _ in range(10)]
    cr = MT19937Cracker(call="random", seed_int_limit=1 << 20)
    cr.feed(obs)
    assert cr.recover()
    assert cr.predict(10) == future


@pytest.mark.slow
def test_partial_randint_best_effort_state():
    # State solve (no seed): rejection is modelled as the no-rejection case, so a
    # large range (negligible rejection) recovers; recover() returns True only if
    # the holdout verified.
    r = random.Random(7)
    n = 1700
    hi = (1 << 30) - 2  # width 2**30 - 1, k = 30, reject prob ~2**-30
    obs = [r.randint(0, hi) for _ in range(n)]
    future = [r.randint(0, hi) for _ in range(10)]
    cr = MT19937Cracker(call="randint", lo=0, hi=hi, try_seed=False)
    cr.feed(obs)
    assert cr.recover()
    assert cr.predict(10) == future


@pytest.mark.slow
def test_partial_random_forward_state():
    r = random.Random(31337)
    n = 950
    obs = [r.random() for _ in range(n)]
    future = [r.random() for _ in range(10)]
    cr = MT19937Cracker(call="random", try_seed=False)
    cr.feed(obs)
    assert cr.recover()
    assert cr.verified
    assert cr.predict(10) == future
