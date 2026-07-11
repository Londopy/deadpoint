"""Secure-by-default helpers — WRAPPERS ONLY.

Every function here is a thin, hard-to-misuse wrapper over a vetted library
(:mod:`secrets`, :mod:`os`, and — for authenticated encryption — the
``cryptography`` package's AEAD primitives).  **This module implements no
cryptographic primitive of its own.**  deadpoint's entire thesis is that you
should not roll your own RNG or crypto; this file is that principle expressed in
code (see spec non-goals N1/N2).
"""

from __future__ import annotations

import os
import secrets


def token_hex(nbytes: int = 32) -> str:
    """A URL-unsafe hex token. Wraps ``secrets.token_hex``; implements nothing."""
    return secrets.token_hex(nbytes)


def token_urlsafe(nbytes: int = 32) -> str:
    """A URL-safe token. Wraps ``secrets.token_urlsafe``; implements nothing."""
    return secrets.token_urlsafe(nbytes)


def token_bytes(nbytes: int = 32) -> bytes:
    """Raw CSPRNG bytes. Wraps ``secrets.token_bytes``; implements nothing."""
    return secrets.token_bytes(nbytes)


def key_bytes(nbytes: int = 32) -> bytes:
    """A symmetric key's worth of CSPRNG bytes. Wraps ``os.urandom``."""
    return os.urandom(nbytes)


def randbelow(n: int) -> int:
    """Uniform int in ``[0, n)`` from the CSPRNG. Wraps ``secrets.randbelow``."""
    return secrets.randbelow(n)


def randint(a: int, b: int) -> int:
    """Uniform int in ``[a, b]`` from the CSPRNG. Wraps ``secrets.randbelow``."""
    return a + secrets.randbelow(b - a + 1)


def choice(seq):
    """Uniform choice from ``seq`` using the CSPRNG. Wraps ``secrets.choice``."""
    return secrets.choice(seq)


# --- authenticated encryption (optional; requires `cryptography`) -----------
def seal(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Authenticated-encrypt with AES-256-GCM.

    Wraps ``cryptography``'s :class:`AESGCM`; implements no primitive.  Returns
    ``nonce || ciphertext`` (nonce is 12 fresh CSPRNG bytes).  ``key`` must be 32
    bytes (use :func:`key_bytes`).
    """
    AESGCM = _aesgcm()
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def open_sealed(key: bytes, sealed: bytes, associated_data: bytes | None = None) -> bytes:
    """Authenticated-decrypt output of :func:`seal`. Wraps ``cryptography`` AESGCM."""
    AESGCM = _aesgcm()
    nonce, ct = sealed[:12], sealed[12:]
    return AESGCM(key).decrypt(nonce, ct, associated_data)


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "seal/open require the 'cryptography' package: pip install deadpoint[remediate]"
        ) from exc
    return AESGCM
