from deadpoint.exploit import xorshift


def test_v8_recover_and_predict_exact():
    eng = xorshift.XorShift128Plus(0x123456789ABCDEF, 0xFEDCBA987654321)
    seq = eng.next_doubles(10)
    cr = xorshift.V8Cracker()
    assert cr.feed_and_recover(seq[:5])
    assert cr.predict(5) == seq[5:]


def test_v8_recover_state_matches_reference():
    s0, s1 = 0xDEADBEEFCAFE, 0x0BADF00D1234
    eng = xorshift.XorShift128Plus(s0, s1)
    seq = eng.next_doubles(4)
    st = xorshift.recover_state(seq)
    assert st is not None
    # a clone from the recovered state reproduces the sequence exactly
    assert xorshift.XorShift128Plus(*st).next_doubles(4) == seq


def test_v8_unbatch_reverses_blocks():
    vals = list(range(64)) + list(range(100, 110))
    un = xorshift.v8_unbatch([float(v) for v in vals])
    assert un[:64] == [float(v) for v in reversed(range(64))]
