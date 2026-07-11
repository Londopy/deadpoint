from deadpoint.model import DetectReport, Verdict, PRNGType, Risk
from deadpoint.remediate import harden, codegen, secure_helpers


SNIPPET = """import random, time
random.seed(int(time.time()))
def reset_token():
    return random.randint(1000, 9999)
key = random.getrandbits(256)
pick = random.choice(users)
"""


def test_codegen_scan_finds_all_usages():
    findings = codegen.scan(SNIPPET)
    calls = {f["call"] for f in findings}
    assert {"seed", "randint", "getrandbits", "choice"} <= calls


def test_codegen_rewrite_produces_secure_calls():
    fixed = codegen.rewrite(SNIPPET)
    assert "secrets.randbelow" in fixed
    assert "os.urandom" in fixed
    assert "import secrets" in fixed


def test_codegen_diff_nonempty():
    assert codegen.diff(SNIPPET).startswith("---")


def test_harden_weak_report_is_critical():
    det = DetectReport(Verdict.WEAK, PRNGType.MT19937, 0.99, {})
    rep = harden(det, snippet=SNIPPET)
    assert any(f.risk == Risk.CRITICAL for f in rep.findings)
    assert rep.suggested_patches


def test_harden_strong_report_is_info():
    det = DetectReport(Verdict.STRONG, PRNGType.CSPRNG, 0.8, {})
    rep = harden(det)
    assert all(f.risk == Risk.INFO for f in rep.findings)


def test_secure_helpers_are_csprng_backed():
    assert len(secure_helpers.token_bytes(16)) == 16
    assert 0 <= secure_helpers.randint(5, 10) <= 10
    assert secure_helpers.token_hex(8) != secure_helpers.token_hex(8)


def test_seal_open_roundtrip_if_cryptography_available():
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return
    key = secure_helpers.key_bytes(32)
    sealed = secure_helpers.seal(key, b"hello", b"aad")
    assert secure_helpers.open_sealed(key, sealed, b"aad") == b"hello"
