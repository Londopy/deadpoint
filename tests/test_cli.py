import random

from deadpoint.cli import main


def _write_hex(path, n=700, seed=123):
    r = random.Random(seed)
    path.write_text("\n".join(hex(r.getrandbits(32)) for _ in range(n)))


def test_cli_analyze(tmp_path, capsys):
    f = tmp_path / "tok.txt"
    _write_hex(f)
    rc = main(["analyze", str(f), "--fmt", "hex", "--width", "32"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "WEAK" in out and "MT19937" in out


def test_cli_predict_json(tmp_path, capsys):
    f = tmp_path / "tok.txt"
    _write_hex(f)
    rc = main(["predict", str(f), "--fmt", "hex", "--forward", "3", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "predictions_forward" in out


def test_cli_report(tmp_path, capsys):
    f = tmp_path / "tok.txt"
    _write_hex(f)
    rc = main(["report", str(f), "--fmt", "hex", "--forward", "3", "--backward", "3"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "RNG ANALYSIS REPORT" in out
    assert "CRITICAL" in out


def test_cli_harden_snippet(tmp_path, capsys):
    snip = tmp_path / "s.py"
    snip.write_text("import random\nt = random.randint(0, 9)\n")
    rc = main(["harden", str(snip), "--snippet", str(snip)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "secrets" in out
