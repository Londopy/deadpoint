"""deadpoint — purple-team RNG analysis toolkit.

Pipeline:  DETECT -> EXPLOIT -> REMEDIATE  (blue -> red -> blue)

Detect whether a "random" value stream is CSPRNG-quality or a known weak PRNG,
prove exploitability by recovering the generator's state (including partial /
truncated outputs via an SMT model) and predicting forward and backward, then
report the correct CSPRNG remediation.

This is an AUDITING / defensive-research tool: use it only on systems you own or
are authorized to test.
"""

from __future__ import annotations

from .model import (
    NormalizedStream, DetectReport, ExploitReport, RemediateReport,
    PRNGType, Verdict, Risk, Finding,
)
from .ingest import ingest
from .detect import analyze
from .remediate import harden
from .exploit import MT19937Cracker
from .report import build_report, format_text, exploit_stream

__version__ = "0.2.0"

__all__ = [
    "ingest",
    "analyze",
    "harden",
    "MT19937Cracker",
    "build_report",
    "format_text",
    "exploit_stream",
    "NormalizedStream",
    "DetectReport",
    "ExploitReport",
    "RemediateReport",
    "PRNGType",
    "Verdict",
    "Risk",
    "Finding",
    "__version__",
]
