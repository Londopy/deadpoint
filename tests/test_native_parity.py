"""Rust-parity test: the native accelerator must match pure Python exactly.

Skipped automatically when the optional ``deadpoint_native`` module is not built
(``maturin develop`` inside ``native/``).  When it *is* built, deadpoint imports
it transparently, so this guards the "identical results" contract from spec M9.
"""

import importlib
import random

import pytest

# Import the submodule explicitly: the `untemper` function re-exported from
# deadpoint.exploit shadows the module name under normal attribute access.
U = importlib.import_module("deadpoint.exploit.untemper")

pytestmark = pytest.mark.skipif(not U.NATIVE, reason="native module not built")


def test_native_untemper_matches_python():
    for _ in range(5000):
        y = random.getrandbits(32)
        assert U._native_untemper(y) == U._untemper_py(y)


def test_native_recover_state_words_matches_python():
    import deadpoint_native

    r = random.Random(2026)
    outs = [r.getrandbits(32) for _ in range(624)]
    native = deadpoint_native.recover_state_words(outs)
    py = [U._untemper_py(o) for o in outs]
    assert native == py
