from deadpoint.demo import make_streams, run_diff, format_diff
from deadpoint.model import Verdict


def test_demo_weak_vs_strong():
    weak, strong = make_streams(n=700, seed=2026)
    result = run_diff(weak, strong)
    (_, w_det, w_exp) = result["weak"]
    (_, s_det, s_exp) = result["strong"]
    assert w_det.verdict == Verdict.WEAK
    assert w_exp is not None and w_exp.recovered and w_exp.verified
    assert s_det.verdict == Verdict.STRONG
    assert s_exp is None  # nothing to exploit


def test_demo_format_contains_both_columns():
    result = run_diff(*make_streams(n=700, seed=7))
    text = format_diff(result)
    assert "WEAK" in text and "STRONG" in text and "secrets" in text
