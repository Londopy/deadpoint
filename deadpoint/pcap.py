"""pcap token / nonce stream extraction (bonus / stretch goal).

Ingest an already-captured ``.pcap`` (classic libpcap format), pull the packet
payloads, and extract a value stream — Modbus transaction IDs, pairing codes,
challenge nonces, transaction IDs in industrial protocols, etc.  This keeps v1's
non-goal intact (deadpoint ingests an *already-extracted* stream) while giving a
convenient on-ramp from raw captures.

No third-party dependency: the classic pcap container is parsed directly.
(pcapng is not handled here — convert with ``editcap`` / ``tshark`` if needed.)
"""

from __future__ import annotations

import struct
from typing import Callable

from .model import NormalizedStream

_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_BE = b"\xa1\xb2\xc3\xd4"


def read_pcap_payloads(path: str) -> list[bytes]:
    """Return the raw per-record bytes of a classic pcap file, in order."""
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_pcap_bytes(data)


def parse_pcap_bytes(data: bytes) -> list[bytes]:
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic == _MAGIC_LE:
        endian = "<"
    elif magic == _MAGIC_BE:
        endian = ">"
    else:
        raise ValueError("not a classic pcap file (bad magic; pcapng not supported)")
    off = 24  # skip the 24-byte global header
    payloads: list[bytes] = []
    while off + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[off : off + 16]
        )
        off += 16
        if off + incl_len > len(data):
            break
        payloads.append(data[off : off + incl_len])
        off += incl_len
    return payloads


def offset_extractor(offset: int, nbytes: int, endian: str = "big") -> Callable:
    """Extract a ``nbytes``-wide integer at a fixed byte ``offset`` in each record."""
    order = "little" if endian == "little" else "big"

    def _extract(pkt: bytes) -> int | None:
        if len(pkt) < offset + nbytes:
            return None
        return int.from_bytes(pkt[offset : offset + nbytes], order)

    return _extract


def extract_stream(
    path: str,
    extract: Callable,
    width: int = 32,
) -> NormalizedStream:
    """Read a pcap and build a :class:`NormalizedStream` via ``extract(pkt)``.

    ``extract`` maps each record's bytes to an ``int`` (or ``None`` to skip).
    Use :func:`offset_extractor` for a fixed-position field, or supply your own.
    """
    values: list[int] = []
    for pkt in read_pcap_payloads(path):
        v = extract(pkt)
        if v is not None:
            values.append(int(v) & ((1 << width) - 1))
    return NormalizedStream(values, width, {"source": path, "records_used": len(values)})
