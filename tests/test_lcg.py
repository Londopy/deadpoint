from deadpoint.exploit import lcg


def test_generic_lcg_recovery_and_predict():
    p = lcg.LCGParams(2**31, 1103515245, 12345)
    x, seq = 42, []
    for _ in range(12):
        x = p.next(x)
        seq.append(x)
    rec = lcg.recover_lcg(seq)
    assert rec is not None
    assert rec.multiplier == p.multiplier
    assert rec.increment == p.increment
    assert p.modulus % rec.modulus == 0 or rec.modulus % p.modulus == 0
    nxt = lcg.predict_lcg(rec, seq[-1], 3)
    assert nxt[0] == p.next(seq[-1])


def test_java_random_recovery():
    def jnext(s):
        return (0x5DEECE66D * s + 0xB) & (2**48 - 1)

    s0 = 987654321 & (2**48 - 1)
    s1 = jnext(s0)
    s2 = jnext(s1)
    o1, o2 = s1 >> 16, s2 >> 16
    state = lcg.recover_java_seed(o1, o2)
    assert state == s1
    assert lcg.java_predict(state, 1) == [o2]
