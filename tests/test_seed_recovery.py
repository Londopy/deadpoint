import random
import time

from deadpoint.exploit import seed_recovery


def test_int_seed_recovery():
    r = random.Random(31415)
    obs = [r.getrandbits(32) for _ in range(4)]
    res = seed_recovery.recover_int_seed(obs, 0, 40000)
    assert res is not None and res.seed == 31415


def test_time_seed_recovery():
    ts = int(time.time())
    r = random.Random(ts)
    obs = [r.getrandbits(32) for _ in range(4)]
    res = seed_recovery.recover_time_seed(obs, center=ts, window_s=60)
    assert res is not None and res.seed == ts


def test_seed_recovery_returns_none_when_absent():
    r = random.Random(999999)
    obs = [r.getrandbits(32) for _ in range(4)]
    assert seed_recovery.recover_int_seed(obs, 0, 100) is None
