import random

from hypothesis import given, settings, strategies as st

from deadpoint.exploit import MT19937Cracker


@settings(deadline=None, max_examples=30)
@given(seed=st.integers(min_value=0, max_value=2**64 - 1),
       n=st.integers(min_value=0, max_value=25))
def test_clean_forward_prediction_exact(seed, n):
    r = random.Random(seed)
    stream = [r.getrandbits(32) for _ in range(624)]
    future = [r.getrandbits(32) for _ in range(n)]
    cr = MT19937Cracker(call="getrandbits", nbits=32)
    cr.feed(stream)
    assert cr.recover()
    assert cr.verified
    assert cr.predict(n) == future


@settings(deadline=None, max_examples=20)
@given(seed=st.integers(min_value=0, max_value=2**64 - 1),
       p=st.integers(min_value=1, max_value=200))
def test_rewind_matches_prior_outputs(seed, p):
    r = random.Random(seed)
    prior = [r.getrandbits(32) for _ in range(p)]     # generated before the stream
    stream = [r.getrandbits(32) for _ in range(624)]
    cr = MT19937Cracker(call="getrandbits", nbits=32)
    cr.feed(stream)
    assert cr.recover()
    assert cr.rewind(p) == prior


def test_recover_fails_below_624():
    cr = MT19937Cracker(call="getrandbits", nbits=32)
    cr.feed([1, 2, 3])
    assert cr.recover() is False


def test_predict_matches_beyond_fed_window():
    # feed more than 624 to check consumed-tracking is correct
    r = random.Random(99)
    stream = [r.getrandbits(32) for _ in range(700)]
    future = [r.getrandbits(32) for _ in range(10)]
    cr = MT19937Cracker(call="getrandbits", nbits=32)
    cr.feed(stream)
    assert cr.recover()
    assert cr.predict(10) == future
