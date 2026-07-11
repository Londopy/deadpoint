"""Typed data model shared across all stages.

Every stage of the pipeline (ingest -> detect -> exploit -> remediate) takes and
returns these dataclasses, so each stage is independently testable and the whole
library is usable without the CLI.  See spec section 9.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class PRNGType(str, Enum):
    """Generator families deadpoint can recognise / attack."""

    MT19937 = "MT19937"
    LCG_JAVA = "LCG_JAVA"
    LCG_GENERIC = "LCG_GENERIC"
    XORSHIFT = "XORSHIFT"
    CSPRNG = "CSPRNG"
    UNKNOWN = "UNKNOWN"


class Verdict(str, Enum):
    """High-level classification of a value stream."""

    WEAK = "WEAK"
    STRONG = "STRONG"
    UNKNOWN = "UNKNOWN"


class Risk(str, Enum):
    """Report risk rating."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class NormalizedStream:
    """Canonical, order-preserving stream of unsigned integers plus metadata."""

    values: list[int]
    width: int
    source_meta: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.values)


@dataclass
class DetectReport:
    """Output of STAGE 1 - DETECT."""

    verdict: Verdict
    suspected: PRNGType
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["suspected"] = self.suspected.value
        return d


@dataclass
class ExploitReport:
    """Output of STAGE 2 - EXPLOIT (the project core)."""

    recovered: bool
    method: str
    state: Any = None
    seed: int | None = None
    predictions_forward: list[int] = field(default_factory=list)
    predictions_backward: list[int] = field(default_factory=list)
    samples_required: int = 0
    verified: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # state may be a large tuple; summarise it for JSON friendliness.
        if isinstance(self.state, (list, tuple)):
            d["state"] = {"kind": "mt_state", "words": len(self.state)}
        return d


@dataclass
class Finding:
    """A single weak-usage finding for the remediate stage."""

    usage: str
    risk: Risk
    explanation: str
    fix: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk"] = self.risk.value
        return d


@dataclass
class RemediateReport:
    """Output of STAGE 3 - REMEDIATE."""

    findings: list[Finding] = field(default_factory=list)
    suggested_patches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "suggested_patches": self.suggested_patches,
        }
