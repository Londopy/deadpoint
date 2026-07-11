"""diff-against-secrets demo mode (stretch goal).

Runs deadpoint's *identical* detection + exploitation pipeline on two streams
side by side — one from a weak PRNG (``random``), one from a CSPRNG
(``secrets``) — to show the contrast in one shot.  Great for a README/GIF and for
making the "use ``secrets``" point viscerally.
"""

from __future__ import annotations

import random
import secrets

from .model import NormalizedStream, Verdict
from .detect import analyze
from .report import exploit_stream


def make_streams(n: int = 700, seed: int | None = None) -> tuple[NormalizedStream, NormalizedStream]:
    """Produce a weak (``random``) and a strong (``secrets``) 32-bit stream."""
    r = random.Random(seed if seed is not None else secrets.randbelow(1 << 30))
    weak = NormalizedStream([r.getrandbits(32) for _ in range(n)], 32, {"source": "random.getrandbits"})
    strong = NormalizedStream([secrets.randbits(32) for _ in range(n)], 32, {"source": "secrets.randbits"})
    return weak, strong


def run_diff(weak: NormalizedStream, strong: NormalizedStream) -> dict:
    """Analyse both streams; attempt exploitation on each."""
    wd = analyze(weak)
    sd = analyze(strong)
    we = exploit_stream(weak, forward=5, backward=0) if wd.verdict == Verdict.WEAK else None
    se = exploit_stream(strong, forward=5, backward=0) if sd.verdict == Verdict.WEAK else None
    return {"weak": (weak, wd, we), "strong": (strong, sd, se)}


def format_diff(result: dict) -> str:
    (w_stream, w_det, w_exp) = result["weak"]
    (s_stream, s_det, s_exp) = result["strong"]

    def col(det, exp, label, source):
        lines = [label, "  source     : " + source,
                 f"  verdict    : {det.verdict.value}",
                 f"  suspected  : {det.suspected.value}",
                 f"  confidence : {det.confidence:.2f}"]
        if exp and exp.recovered:
            lines.append(f"  EXPLOIT    : state recovered, verified={exp.verified}")
            lines.append(f"  next 3     : {exp.predictions_forward[:3]}")
        else:
            lines.append("  EXPLOIT    : not recoverable (no state to steal)")
        return lines

    left = col(w_det, w_exp, "WEAK  — random", w_stream.source_meta.get("source", "random"))
    right = col(s_det, s_exp, "STRONG — secrets", s_stream.source_meta.get("source", "secrets"))
    width = max(len(x) for x in left) + 3
    out = ["=" * 72, "  deadpoint — diff against secrets", "=" * 72]
    for a, b in zip(left, right):
        out.append(f"{a:<{width}} | {b}")
    out.append("-" * 72)
    out.append("Same tool, same pipeline. One stream leaks its future; the other")
    out.append("gives deadpoint nothing. That difference is `secrets` / `os.urandom`.")
    out.append("=" * 72)
    return "\n".join(out)
