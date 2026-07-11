"""STAGE 3 - REMEDIATE (blue): map weaknesses to vetted CSPRNG fixes."""

from __future__ import annotations

from ..model import DetectReport, RemediateReport, Finding, Risk, Verdict
from .mappings import MAPPINGS, Mapping
from . import codegen, secure_helpers


def harden(report: DetectReport, snippet: str | None = None) -> RemediateReport:
    """Produce remediation findings (and optional patches) from a detect report."""
    findings: list[Finding] = []
    patches: list[str] = []

    if report.verdict == Verdict.WEAK:
        risk = Risk.CRITICAL if report.confidence >= 0.9 else Risk.HIGH
        fam = report.suspected.value
        findings.append(
            Finding(
                usage=f"Weak generator in use ({fam})",
                risk=risk,
                explanation=(
                    f"The stream is consistent with {fam}, a non-cryptographic PRNG. "
                    "Its output is predictable and its internal state is recoverable "
                    "from observed values (CWE-338)."
                ),
                fix="Replace the generator with secrets / os.urandom for any "
                    "security-relevant value (tokens, keys, nonces, IDs).",
            )
        )
        for m in _relevant_mappings(report):
            findings.append(
                Finding(usage=m.weak, risk=Risk.HIGH, explanation=m.why, fix=m.secure)
            )
    elif report.verdict == Verdict.STRONG:
        findings.append(
            Finding(
                usage="No weak generator detected",
                risk=Risk.INFO,
                explanation="Stream is consistent with a CSPRNG; no state recovery "
                            "succeeded and the statistical battery passed.",
                fix="Keep using secrets / os.urandom. No change required.",
            )
        )
    else:
        findings.append(
            Finding(
                usage="Unclassified stream",
                risk=Risk.MEDIUM,
                explanation="Statistical anomalies were present but no known weak "
                            "family was recovered. Investigate the source manually.",
                fix="Confirm the source; prefer secrets / os.urandom for anything "
                    "security-relevant.",
            )
        )

    if snippet:
        for f in codegen.scan(snippet):
            findings.append(
                Finding(usage=f"{f['text']} (line {f['line']})", risk=Risk.HIGH,
                        explanation=f["why"], fix=f["fix"])
            )
        patch = codegen.diff(snippet)
        if patch:
            patches.append(patch)

    return RemediateReport(findings=findings, suggested_patches=patches)


def _relevant_mappings(report: DetectReport) -> list[Mapping]:
    # Surface the most common misuse fixes; the whole table is small.
    return MAPPINGS[:4]


__all__ = ["harden", "RemediateReport", "codegen", "secure_helpers", "MAPPINGS"]
