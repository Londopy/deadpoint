from deadpoint.web import sample_endpoint, regex_extractor


def test_sample_endpoint_with_injected_fetch():
    tokens = ["a3f10b8c", "7c2e9d54", "00000001"]
    it = iter(tokens)

    def fake_fetch(url, headers):
        return {"body": f'{{"session":"{next(it)}"}}', "headers": {}}

    ex = regex_extractor(r'"session":"([0-9a-f]+)"', group=1, base=16)
    s = sample_endpoint("http://example.test/login", 3, ex, fetch=fake_fetch)
    assert s.values == [0xA3F10B8C, 0x7C2E9D54, 1]
    assert s.width == 32
    assert s.source_meta["collected"] == 3


def test_regex_extractor_falls_back_to_headers():
    ex = regex_extractor(r"code=(\d+)", group=1, base=10)

    def fetch(url, headers):
        return {"body": "no token here", "headers": {"Set-Cookie": "code=42; Path=/"}}

    s = sample_endpoint("u", 1, ex, fetch=fetch)
    assert s.values == [42]


def test_sample_endpoint_skips_none():
    def fetch(url, headers):
        return {"body": "nothing", "headers": {}}

    ex = regex_extractor(r"tok=([0-9a-f]+)")
    s = sample_endpoint("u", 3, ex, fetch=fetch)
    assert s.values == []
