from deadpoint.ingest import from_hex, from_base64, from_ints, from_bytes, ingest


def test_hex_tokens():
    s = from_hex("0x01 0x02 deadbeef", width=32)
    assert s.values == [1, 2, 0xDEADBEEF]


def test_hex_blob_chunks():
    s = from_hex("0000000100000002", width=32, endian="big")
    assert s.values == [1, 2]


def test_int_stream():
    s = from_ints([5, 6, 7], width=16)
    assert s.values == [5, 6, 7] and s.width == 16


def test_base64_roundtrip():
    import base64
    data = (1).to_bytes(4, "big") + (2).to_bytes(4, "big")
    tok = base64.b64encode(data).decode()
    s = from_base64([tok], width=32, endian="big")
    assert s.values == [1, 2]


def test_bytes_little_endian():
    s = from_bytes(b"\x01\x00\x00\x00\x02\x00\x00\x00", width=32, endian="little")
    assert s.values == [1, 2]


def test_ingest_from_bytes_source_adds_warnings():
    s = ingest(b"1 2 3", fmt="int", width=32)
    assert "warnings" in s.source_meta
