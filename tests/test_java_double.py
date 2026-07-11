import random

from deadpoint.exploit import lcg


def test_java_nextdouble_recovery_and_predict():
    seed = random.getrandbits(48)
    r = lcg.JavaRandom(seed)
    d0 = r.next_double()
    future = [r.next_double() for _ in range(5)]
    state1 = lcg.recover_java_from_double(d0)
    assert state1 is not None
    assert lcg.java_double_predict(state1, 5) == future


def test_java_nextdouble_deterministic():
    a = lcg.JavaRandom(42)
    b = lcg.JavaRandom(42)
    assert [a.next_double() for _ in range(4)] == [b.next_double() for _ in range(4)]
