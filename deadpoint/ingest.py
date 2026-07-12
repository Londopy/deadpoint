"""INGESTION LAYER — normalize raw values into a canonical uint stream.

Accepts the shapes an auditor actually captures (newline ints, a hex blob, base64
tokens, a raw byte file, or stdin) and produces an order-preserving
:class:`NormalizedStream`.  Order matters: state recovery depends on consecutive
samples, so we preserve it and warn when the samples look non-consecutive.
"""

from __future__ import annotations

import base64
import re
import sys
from typing import Iterable, Literal

from .model import NormalizedStream

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _bytes_to_words(data: bytes, width: int, endian: str) -> list[int]:
    nbytes = width // 8
    if len(data) % nbytes:
        data = data[: len(data) - (len(data) % nbytes)]
    order: Literal["little", "big"] = "little" if endian == "little" else "big"
    return [int.from_bytes(data[i : i + nbytes], order) for i in range(0, len(data), nbytes)]


def from_ints(values: Iterable[int], width: int = 32) -> NormalizedStream:
    vals = [int(v) & ((1 << width) - 1) for v in values]
    return NormalizedStream(vals, width, {"fmt": "int", "count": len(vals)})


def from_hex(text: str, width: int = 32, endian: str = "big") -> NormalizedStream:
    """Parse hex: either newline/space-delimited tokens or one continuous blob."""
    tokens = text.split()
    meta = {"fmt": "hex", "endian": endian}
    if len(tokens) > 1 and all(_HEX_RE.match(t.replace("0x", "")) for t in tokens):
        vals = [int(t, 16) & ((1 << width) - 1) for t in tokens]
        meta["mode"] = "tokens"
        return NormalizedStream(vals, width, meta)
    blob = re.sub(r"\s+", "", text)
    if blob.startswith(("0x", "0X")):
        blob = blob[2:]
    if len(blob) % 2:
        blob = "0" + blob
    data = bytes.fromhex(blob)
    vals = _bytes_to_words(data, width, endian)
    meta["mode"] = "blob"
    return NormalizedStream(vals, width, meta)


def from_base64(tokens: Iterable[str], width: int = 32, endian: str = "big") -> NormalizedStream:
    """Decode base64 tokens to bytes, then chunk to ``width``-bit words."""
    data = b"".join(base64.b64decode(_pad(t)) for t in tokens)
    vals = _bytes_to_words(data, width, endian)
    return NormalizedStream(vals, width, {"fmt": "b64", "endian": endian})


def _pad(t: str) -> str:
    t = t.strip()
    return t + "=" * (-len(t) % 4)


def from_bytes(data: bytes, width: int = 32, endian: str = "big") -> NormalizedStream:
    vals = _bytes_to_words(data, width, endian)
    return NormalizedStream(vals, width, {"fmt": "bytes", "endian": endian})


def ingest(
    source: str | bytes,
    fmt: str = "int",
    width: int = 32,
    endian: str = "big",
) -> NormalizedStream:
    """Ingest from a file path (or ``"-"`` for stdin) in the given format.

    ``source`` may also be raw ``bytes`` (already-read content).  ``fmt`` is one
    of ``int``, ``hex``, ``b64``, ``bytes``.
    """
    if isinstance(source, bytes):
        raw = source
        text = source.decode("utf-8", "replace")
    elif source == "-":
        raw = sys.stdin.buffer.read()
        text = raw.decode("utf-8", "replace")
    else:
        with open(source, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8", "replace")

    if fmt == "int":
        vals = [int(x, 0) for x in text.split()]
        stream = from_ints(vals, width)
    elif fmt == "hex":
        stream = from_hex(text, width, endian)
    elif fmt == "b64":
        stream = from_base64(text.split(), width, endian)
    elif fmt == "bytes":
        stream = from_bytes(raw, width, endian)
    else:
        raise ValueError(f"unknown fmt: {fmt}")

    stream.source_meta["warnings"] = consecutiveness_warnings(stream.values)
    return stream


def consecutiveness_warnings(values: list[int]) -> list[str]:
    """Cheap heuristics that flag possibly non-consecutive / interleaved input."""
    warnings: list[str] = []
    if len(values) < 8:
        warnings.append(f"only {len(values)} samples; most recoveries need many more")
    dupes = len(values) - len(set(values))
    if dupes and len(values) > 32 and dupes > len(values) * 0.02:
        warnings.append(
            f"{dupes} duplicate values: samples may be interleaved from multiple streams"
        )
    return warnings
