import random

from hypothesis import given, strategies as st

from deadpoint.exploit.untemper import temper, untemper, MASK32


@given(st.integers(min_value=0, max_value=MASK32))
def test_untemper_inverts_temper(x):
    assert untemper(temper(x)) == x


def test_untemper_recovers_python_state_words():
    r = random.Random(12345)
    outs = [r.getrandbits(32) for _ in range(50)]
    # untemper of a getrandbits(32) output is the raw state word Python tempered.
    for o in outs:
        assert temper(untemper(o)) == o
