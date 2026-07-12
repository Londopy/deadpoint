import asyncio
import random

import pytest

from deadpoint import tui
from deadpoint.report import build_report
from deadpoint.model import NormalizedStream, Verdict


def _weak_report():
    r = random.Random(2026)
    stream = NormalizedStream([r.getrandbits(32) for _ in range(700)], 32, {})
    return build_report(stream, forward=5, backward=3)


def _strong_report():
    import secrets
    stream = NormalizedStream([secrets.randbits(32) for _ in range(700)], 32, {})
    return build_report(stream, forward=5, backward=3)


# --- pure formatters (no Textual needed) ------------------------------------
def test_detect_panel_shows_verdict():
    rep = _weak_report()
    panel = tui.detect_panel(rep)
    assert "DETECT" in panel and rep.detect.verdict.value in panel


def test_exploit_panel_weak_vs_strong():
    assert "Recovered" in tui.exploit_panel(_weak_report())
    assert "No weak generator" in tui.exploit_panel(_strong_report())


def test_prediction_rows_count():
    rows = tui.prediction_rows(_weak_report())
    assert len(rows) == 5
    assert all(len(r) == 3 for r in rows)
    assert tui.prediction_rows(_strong_report()) == []


def test_remediate_panel_has_risk():
    assert "REMEDIATE" in tui.remediate_panel(_weak_report())


def test_build_helper(tmp_path):
    r = random.Random(7)
    f = tmp_path / "t.txt"
    f.write_text("\n".join(hex(r.getrandbits(32)) for _ in range(700)))
    rep = tui.build(str(f), fmt="hex", width=32, forward=3, backward=2)
    assert rep.detect.verdict == Verdict.WEAK


# --- headless app smoke (requires Textual) ----------------------------------
@pytest.mark.skipif(not tui._HAS_TEXTUAL, reason="Textual not installed")
def test_app_runs_headless(tmp_path):
    r = random.Random(2026)
    f = tmp_path / "tok.txt"
    f.write_text("\n".join(hex(r.getrandbits(32)) for _ in range(700)))

    async def _drive():
        app = tui.DeadpointTUI(source=str(f), fmt="hex", width=32, forward=5, backward=3)
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.report is not None
            assert app.report.detect.verdict == Verdict.WEAK
            assert app.query_one("#preds").row_count == 5
            await app.action_quit()

    asyncio.run(_drive())
