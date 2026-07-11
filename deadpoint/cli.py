"""deadpoint command-line interface (STAGE-spanning UX).

Subcommands: ``analyze`` (detect only), ``recover`` (state/seed), ``predict``
(recover + forward/backward), ``harden`` (remediation), ``report`` (full
pipeline).  Plain-text output by default; ``--json`` everywhere.
"""

from __future__ import annotations

import argparse
import json
import sys

from .ingest import ingest
from .detect import analyze
from .remediate import harden
from .report import build_report, format_text, exploit_stream


def _load(args) -> "object":
    return ingest(args.input, fmt=args.fmt, width=args.width, endian=args.endian)


def _add_common(p) -> None:
    p.add_argument("input", help="input file, or '-' for stdin")
    p.add_argument("--fmt", default="int", choices=["int", "hex", "b64", "bytes"])
    p.add_argument("--width", type=int, default=32, choices=[8, 16, 32, 64])
    p.add_argument("--endian", default="big", choices=["big", "little"])
    p.add_argument("--json", action="store_true", help="emit JSON")


def _add_call(p) -> None:
    p.add_argument("--call", default="getrandbits",
                   choices=["getrandbits", "raw", "random", "randint", "randrange"])
    p.add_argument("--nbits", type=int, default=32)
    p.add_argument("--lo", type=int, default=None)
    p.add_argument("--hi", type=int, default=None)


def cmd_analyze(args) -> int:
    stream = _load(args)
    report = analyze(stream, seed_checks=args.seed_checks)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"Verdict   : {report.verdict.value}")
        print(f"Suspected : {report.suspected.value}")
        print(f"Confidence: {report.confidence:.2f}")
        stats = report.evidence.get("stats", {})
        print(f"Stats     : {stats.get('tests_passed')} passed "
              f"(looks_random={stats.get('looks_random')})")
    return 0


def cmd_recover(args) -> int:
    stream = _load(args)
    e = exploit_stream(stream, call=args.call, nbits=args.nbits, lo=args.lo,
                       hi=args.hi, forward=0, backward=0)
    if args.json:
        print(json.dumps(e.to_dict(), indent=2))
    else:
        print(f"Recovered : {e.recovered}  (method: {e.method})")
        print(f"Verified  : {e.verified}")
        print(f"Samples   : recommended >= {e.samples_required}")
        if e.notes:
            print(f"Note      : {e.notes}")
    return 0 if e.recovered else 2


def cmd_predict(args) -> int:
    stream = _load(args)
    e = exploit_stream(stream, call=args.call, nbits=args.nbits, lo=args.lo,
                       hi=args.hi, forward=args.forward, backward=args.backward)
    if args.json:
        print(json.dumps(e.to_dict(), indent=2))
    else:
        if not e.recovered:
            print(f"Recovery failed: {e.notes}")
            return 2
        print(f"forward ({args.forward}): {e.predictions_forward}")
        if args.backward:
            print(f"backward ({args.backward}): {e.predictions_backward}")
    return 0 if e.recovered else 2


def cmd_harden(args) -> int:
    snippet = None
    if args.snippet:
        with open(args.snippet, encoding="utf-8") as fh:
            snippet = fh.read()
        from .model import DetectReport, Verdict, PRNGType
        detect = DetectReport(Verdict.WEAK, PRNGType.MT19937, 0.9, {})
    else:
        stream = _load(args)
        detect = analyze(stream)
    report = harden(detect, snippet=snippet)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        for f in report.findings:
            print(f"[{f.risk.value}] {f.usage}\n    fix: {f.fix}")
        for patch in report.suggested_patches:
            print("\n" + patch)
    return 0


def cmd_report(args) -> int:
    stream = _load(args)
    snippet = None
    if getattr(args, "snippet", None):
        with open(args.snippet, encoding="utf-8") as fh:
            snippet = fh.read()
    full = build_report(stream, call=args.call, nbits=args.nbits, lo=args.lo,
                        hi=args.hi, forward=args.forward, backward=args.backward,
                        snippet=snippet)
    text = format_text(full)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if args.json:
        js = full.to_json()
        if isinstance(args.json, str):
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(js)
        else:
            print(js)
    if not args.json or args.out is None:
        print(text)
    return 0


def cmd_demo(args) -> int:
    from .demo import make_streams, run_diff, format_diff
    weak, strong = make_streams(n=args.count, seed=args.seed)
    result = run_diff(weak, strong)
    if args.json:
        import json as _json
        (_, wd, we), (_, sd, se) = result["weak"], result["strong"]
        print(_json.dumps({
            "weak": {"detect": wd.to_dict(), "exploit": we.to_dict() if we else None},
            "strong": {"detect": sd.to_dict(), "exploit": se.to_dict() if se else None},
        }, indent=2))
    else:
        print(format_diff(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deadpoint",
        description="Purple-team RNG analysis: detect -> exploit -> remediate.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="detect only: verdict + suspected generator")
    _add_common(a)
    a.add_argument("--seed-checks", action="store_true",
                   help="also brute-force time/small seeds (slower)")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("recover", help="recover state/seed; report samples required")
    _add_common(r)
    _add_call(r)
    r.set_defaults(func=cmd_recover)

    pr = sub.add_parser("predict", help="recover then output predicted future/past")
    _add_common(pr)
    _add_call(pr)
    pr.add_argument("--forward", type=int, default=10)
    pr.add_argument("--backward", type=int, default=0)
    pr.set_defaults(func=cmd_predict)

    h = sub.add_parser("harden", help="remediation report + suggested patch")
    _add_common(h)
    h.add_argument("--snippet", help="analyse a source file for weak random usage")
    h.set_defaults(func=cmd_harden)

    rp = sub.add_parser("report", help="full pipeline: detect -> exploit -> remediate")
    _add_common(rp)
    _add_call(rp)
    rp.add_argument("--forward", type=int, default=10)
    rp.add_argument("--backward", type=int, default=5)
    rp.add_argument("--snippet", help="also scan a source file")
    rp.add_argument("--out", help="write plain-text report to this path")
    rp.set_defaults(func=cmd_report)

    dm = sub.add_parser("demo", help="diff-against-secrets: weak vs CSPRNG side by side")
    dm.add_argument("--count", type=int, default=700)
    dm.add_argument("--seed", type=int, default=None)
    dm.add_argument("--json", action="store_true")
    dm.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
