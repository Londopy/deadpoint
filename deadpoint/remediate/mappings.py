"""Misuse -> fix mapping table for STAGE 3 - REMEDIATE.

Each entry maps a weak ``random`` usage to the correct CSPRNG replacement and a
one-line rationale.  The remediate stage and the codegen patcher both read from
this table so advice and generated code never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mapping:
    weak: str
    secure: str
    why: str


MAPPINGS: list[Mapping] = [
    Mapping(
        "random.random()",
        "secrets.randbelow(1 << 53) / (1 << 53)",
        "random.random() is MT19937 — predictable. Use CSPRNG bits if a secure "
        "float is truly needed (usually it isn't).",
    ),
    Mapping(
        "random.randint(a, b)",
        "a + secrets.randbelow(b - a + 1)",
        "randint draws from MT19937; secrets.randbelow is CSPRNG-backed and "
        "unbiased.",
    ),
    Mapping(
        "random.randrange(n)",
        "secrets.randbelow(n)",
        "Same weakness; secrets.randbelow is the drop-in secure equivalent.",
    ),
    Mapping(
        "random.choice(seq)",
        "secrets.choice(seq)",
        "secrets.choice selects uniformly using the CSPRNG.",
    ),
    Mapping(
        "random.getrandbits(k)",
        "int.from_bytes(os.urandom((k + 7) // 8), 'big') >> (-k % 8)",
        "getrandbits exposes raw MT19937 words; derive bits from os.urandom "
        "instead.",
    ),
    Mapping(
        "token = ''.join(random.choice(alphabet) ...)",
        "secrets.token_urlsafe(nbytes)",
        "Session/reset tokens must be unpredictable: use secrets.token_urlsafe / "
        "token_hex.",
    ),
    Mapping(
        "key = random.getrandbits(256)",
        "secrets.token_bytes(32)  # or os.urandom(32)",
        "Key material from MT19937 is fully recoverable; use a CSPRNG.",
    ),
    Mapping(
        "random.seed(int(time.time()))",
        "# remove seeding entirely; use secrets / os.urandom",
        "A time seed is brute-forceable in seconds. Security RNGs are not seeded "
        "by the caller.",
    ),
]


# Convenience index by the leading call token (e.g. "randint").
BY_CALL = {
    "random": MAPPINGS[0],
    "randint": MAPPINGS[1],
    "randrange": MAPPINGS[2],
    "choice": MAPPINGS[3],
    "getrandbits": MAPPINGS[4],
    "token": MAPPINGS[5],
    "key": MAPPINGS[6],
    "seed": MAPPINGS[7],
}
