import pytest

from deadpoint.exploit import php


def test_php_engine_deterministic():
    a = php.PHPMt19937(1234567)
    b = php.PHPMt19937(1234567)
    assert [a.mt_rand() for _ in range(5)] == [b.mt_rand() for _ in range(5)]


def test_php_output_is_31_bit():
    eng = php.PHPMt19937(99)
    assert all(0 <= eng.mt_rand() <= php.PHP_MT_RAND_MAX for _ in range(200))


def test_php_seed_recovery():
    eng = php.PHPMt19937(4242)
    raw = [eng.mt_rand() for _ in range(6)]
    assert php.recover_php_seed(raw, 0, 10000) == 4242


@pytest.mark.slow
def test_php_state_recovery_and_predict():
    eng = php.PHPMt19937(0xC0FFEE)
    raw = [eng.mt_rand() for _ in range(1500)]
    future = [eng.mt_rand() for _ in range(12)]
    cr = php.recover(raw)
    assert cr is not None and cr.verified
    assert cr.predict(12) == future
