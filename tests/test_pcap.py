import struct

from deadpoint.pcap import parse_pcap_bytes, offset_extractor, extract_stream


def _make_pcap(payloads, endian="<"):
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    gh = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
    out = gh
    for p in payloads:
        out += struct.pack(endian + "IIII", 0, 0, len(p), len(p)) + p
    return out


def test_parse_pcap_records():
    payloads = [b"\x00\x00" + (1234).to_bytes(4, "big"),
                b"\x00\x00" + (5678).to_bytes(4, "big")]
    recs = parse_pcap_bytes(_make_pcap(payloads))
    assert len(recs) == 2
    assert recs[0] == payloads[0]


def test_offset_extractor_stream(tmp_path):
    vals = [111, 222, 333, 444]
    payloads = [b"\xaa\xbb" + v.to_bytes(4, "big") for v in vals]
    p = tmp_path / "cap.pcap"
    p.write_bytes(_make_pcap(payloads))
    stream = extract_stream(str(p), offset_extractor(2, 4, "big"), width=32)
    assert stream.values == vals


def test_bad_magic_raises():
    import pytest
    with pytest.raises(ValueError):
        parse_pcap_bytes(b"not a pcap file at all........")
