"""REPORTING — assemble detect -> exploit -> remediate into a report.

Emits both a plain-text report (the default UX) and machine-readable JSON, with a
coarse risk rating.  The rating is CRITICAL when the generator's state was
recovered *and* predictions were verified against held-out output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .model import (
    NormalizedStream, DetectReport, ExploitReport, RemediateReport, Verdict, Risk,
)
from .detect import analyze
from .remediate import harden
from .exploit.mt19937 import MT19937Cracker


@dataclass
class FullReport:
    detect: DetectReport
    exploit: ExploitReport | None
    remediate: RemediateReport
    risk: Risk
    stream_meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk.value,
            "stream": self.stream_meta,
            "detect": self.detect.to_dict(),
            "exploit": self.exploit.to_dict() if self.exploit else None,
            "remediate": self.remediate.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def exploit_stream(
    stream: NormalizedStream,
    call: str = "getrandbits",
    nbits: int = 32,
    lo: int | None = None,
    hi: int | None = None,
    forward: int = 10,
    backward: int = 0,
) -> ExploitReport:
    """Run STAGE 2 on a stream and return an :class:`ExploitReport`."""
    cr = MT19937Cracker(call=call, nbits=nbits, lo=lo, hi=hi)
    cr.feed(stream.values)
    ok = cr.recover()
    if not ok:
        return ExploitReport(
            recovered=False, method=cr.method or "n/a",
            samples_required=cr.samples_required or 0,
            notes="Recovery failed: insufficient samples or unsupported call.",
        )
    fwd = cr.predict(forward) if forward else []
    bwd = []
    if backward and call in ("getrandbits", "raw") and nbits == 32:
        try:
            bwd = cr.rewind(backward)
        except (ValueError, NotImplementedError):
            bwd = []
    return ExploitReport(
        recovered=True, method=cr.method or "", state=cr._block0,
        predictions_forward=fwd, predictions_backward=bwd,
        samples_required=cr.samples_required or 0, verified=cr.verified,
    )


def build_report(
    stream: NormalizedStream,
    call: str = "getrandbits",
    nbits: int = 32,
    lo: int | None = None,
    hi: int | None = None,
    forward: int = 10,
    backward: int = 5,
    snippet: str | None = None,
) -> FullReport:
    detect = analyze(stream)
    exploit = None
    if detect.verdict == Verdict.WEAK:
        exploit = exploit_stream(stream, call, nbits, lo, hi, forward, backward)
    remediate = harden(detect, snippet=snippet)
    risk = _rate(detect, exploit)
    return FullReport(
        detect=detect, exploit=exploit, remediate=remediate, risk=risk,
        stream_meta={"count": len(stream.values), "width": stream.width,
                     **stream.source_meta},
    )


def _rate(detect: DetectReport, exploit: ExploitReport | None) -> Risk:
    if exploit and exploit.recovered and exploit.verified:
        return Risk.CRITICAL
    if exploit and exploit.recovered:
        return Risk.HIGH
    if detect.verdict == Verdict.WEAK:
        return Risk.HIGH
    if detect.verdict == Verdict.STRONG:
        return Risk.INFO
    return Risk.MEDIUM


# --- plain-text rendering ---------------------------------------------------
def format_text(report: FullReport) -> str:
    d, e, r = report.detect, report.exploit, report.remediate
    L = []
    L.append("=" * 70)
    L.append("  DEADPOINT — RNG ANALYSIS REPORT")
    L.append("=" * 70)
    L.append(f"Risk rating      : {report.risk.value}")
    L.append(f"Samples analysed : {report.stream_meta.get('count')} "
             f"({report.stream_meta.get('width')}-bit words)")
    L.append("")
    L.append("-- DETECT " + "-" * 60)
    L.append(f"Verdict          : {d.verdict.value}")
    L.append(f"Suspected family : {d.suspected.value}")
    L.append(f"Confidence       : {d.confidence:.2f}")
    battery = d.evidence.get("stats", {})
    L.append(f"Statistical tests: {battery.get('tests_passed', 'n/a')} passed "
             f"(looks_random={battery.get('looks_random')})")
    L.append("")
    if e is not None:
        L.append("-- EXPLOIT " + "-" * 59)
        L.append(f"State recovered  : {e.recovered}  (method: {e.method})")
        L.append(f"Predictions verified on holdout: {e.verified}")
        if e.predictions_forward:
            preview = ", ".join(str(x) for x in e.predictions_forward[:5])
            L.append(f"Next outputs     : {preview}"
                     f"{' ...' if len(e.predictions_forward) > 5 else ''}")
        if e.predictions_backward:
            preview = ", ".join(str(x) for x in e.predictions_backward[-5:])
            L.append(f"Prior outputs    : ...{preview}")
        L.append("")
    L.append("-- REMEDIATE " + "-" * 57)
    for f in r.findings:
        L.append(f"[{f.risk.value}] {f.usage}")
        L.append(f"      why: {f.explanation}")
        L.append(f"      fix: {f.fix}")
    if r.suggested_patches:
        L.append("")
        L.append("-- SUGGESTED PATCH " + "-" * 51)
        L.append(r.suggested_patches[0])
    L.append("=" * 70)
    L.append("deadpoint is an authorized-testing / self-assessment tool. Only use "
             "it on systems you own or are permitted to test.")
    return "\n".join(L)
