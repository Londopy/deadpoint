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

    if suspected in (PRNGType.MT19937, PRNGType.LCG_GENERIC, PRNGType.LCG_JAVA):
        verdict = Verdict.WEAK
    elif suspected == PRNGType.XORSHIFT:
        verdict = Verdict.WEAK
        confidence = max(confidence, 0.5)
    elif battery["looks_random"]:
        verdict = Verdict.STRONG
        suspected = PRNGType.CSPRNG
        confidence = 0.8
    else:
        verdict = Verdict.UNKNOWN
        confidence = 0.3

    return DetectReport(
        verdict=verdict, suspected=suspected, confidence=confidence, evidence=evidence
    )


__all__ = ["analyze", "DetectReport"]
