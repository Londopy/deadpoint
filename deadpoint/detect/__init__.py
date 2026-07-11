"""STAGE 1 - DETECT (blue): classify a stream and fingerprint its generator."""

from __future__ import annotations

from ..model import NormalizedStream, DetectReport, Verdict, PRNGType
from . import stats as _stats
from . import fingerprint as _fp
from . import seed_heuristics as _seed


def analyze(stream: NormalizedStream, seed_checks: bool = False) -> DetectReport:
    """Run the detect stage: statistics + fingerprint -> :class:`DetectReport`.

    Verdict logic:
      * If a weak generator is *recovered and verified* -> ``WEAK`` (proof).
      * Else if the statistical battery looks random -> ``STRONG`` (consistent
        with a CSPRNG; no weakness found).
      * Else -> ``UNKNOWN`` (anomalous but not attributed to a known family).
    """
    values, width = stream.values, stream.width
    battery = _stats.run_battery(values, width)
    suspected, confidence, evidence = _fp.fingerprint(values, width)
    evidence["stats"] = battery

    if seed_checks:
        evidence["time_seed"] = _seed.check_time_seed(values)
        evidence["small_seed"] = _seed.check_small_seed(values)

    # STRONG rests on a *stable* discriminator — min-entropy per bit, which sits
    # at ~0.99 for any uniform stream — not on the all-pass of threshold-crossing
    # p-value tests (a genuine CSPRNG fails a p<0.01 test ~1% of the time each, so
    # requiring all five to pass would flag ~5% of CSPRNG streams as non-random).
    min_ent = battery.get("entropy", {}).get("min_entropy_per_bit", 0.0)
    looks_uniform = min_ent >= 0.95

    if suspected in (PRNGType.MT19937, PRNGType.LCG_GENERIC, PRNGType.LCG_JAVA):
        verdict = Verdict.WEAK
    elif suspected == PRNGType.XORSHIFT:
        verdict = Verdict.WEAK
        confidence = max(confidence, 0.5)
    elif looks_uniform:
        # Uniform and not recoverable by any known-weak fingerprint => consistent
        # with a CSPRNG (no weakness found).
        verdict = Verdict.STRONG
        suspected = PRNGType.CSPRNG
        confidence = 0.8 if battery["looks_random"] else 0.7
    else:
        verdict = Verdict.UNKNOWN
        confidence = 0.3

    return DetectReport(
        verdict=verdict, suspected=suspected, confidence=confidence, evidence=evidence
    )


__all__ = ["analyze", "DetectReport"]
