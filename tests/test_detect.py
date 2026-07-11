import random
import secrets

from deadpoint.model import NormalizedStream, Verdict, PRNGType
from deadpoint.detect import analyze


def test_mt_stream_classified_weak():
    r = random.Random(2026)
    vals = [r.getrandbits(32) for _ in range(700)]
    rep = analyze(NormalizedStream(vals, 32, {}))
    assert rep.verdict == Verdict.WEAK
    assert rep.suspected == PRNGType.MT19937
    assert rep.confidence > 0.9


def test_secrets_stream_classified_strong():
    vals = [secrets.randbits(32) for _ in range(700)]
    rep = analyze(NormalizedStream(vals, 32, {}))
    # Must NOT be a false "crackable".
    assert rep.verdict == Verdict.STRONG
    assert rep.suspected == PRNGType.CSPRNG


def test_stats_battery_flags_constant_stream():
    vals = [0] * 512
    rep = analyze(NormalizedStream(vals, 32, {}))
    assert rep.verdict != Verdict.STRONG
