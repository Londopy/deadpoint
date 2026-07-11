"""Live-endpoint sampling (bonus / stretch goal).

Pull "random" values straight from a running service — session tokens, CSRF
nonces, pairing codes — and hand them to the detect/exploit pipeline in-loop.

The HTTP fetch is injectable (``fetch=...``) so this is fully testable offline
and so you can plug in your own authenticated client / rate limiter.  Only point
it at endpoints you are authorized to test.
"""

from __future__ import annotations

import re
import time
from typing import Callable

from .model import NormalizedStream


def _default_fetch(url: str, headers: dict) -> dict:
    import urllib.request  # local import so the dep is only needed when used

    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (user-supplied URL)
        body = resp.read().decode("utf-8", "replace")
        return {"body": body, "headers": {k: v for k, v in resp.headers.items()},
                "status": resp.status}


def regex_extractor(pattern: str, group: int = 1, base: int = 16) -> Callable:
    """Build an extractor pulling one integer per response via a regex.

    ``base`` is the int base of the captured group (16 for hex tokens, 10 for
    decimal codes).  Searches the response body, then any header values.
    """
    rx = re.compile(pattern)

    def _extract(resp) -> int | None:
        text = resp["body"] if isinstance(resp, dict) else str(resp)
        m = rx.search(text)
        if not m and isinstance(resp, dict):
            for v in resp.get("headers", {}).values():
                m = rx.search(str(v))
                if m:
                    break
        return int(m.group(group), base) if m else None

    return _extract


def sample_endpoint(
    url: str,
    n: int,
    extract: Callable,
    *,
    fetch: Callable | None = None,
    headers: dict | None = None,
    delay_s: float = 0.0,
    width: int = 32,
) -> NormalizedStream:
    """Sample ``n`` values from ``url`` and return a :class:`NormalizedStream`.

    ``extract(resp)`` maps a fetch result to an ``int`` (or ``None`` to skip).
    ``fetch(url, headers)`` defaults to a plain urllib GET but is injectable.
    ``delay_s`` throttles requests (be a good citizen / avoid WAF trips).
    """
    do_fetch = fetch or _default_fetch
    values: list[int] = []
    for _ in range(n):
        resp = do_fetch(url, headers or {})
        v = extract(resp)
        if v is not None:
            values.append(int(v) & ((1 << width) - 1))
        if delay_s:
            time.sleep(delay_s)
    return NormalizedStream(
        values, width, {"source": url, "requested": n, "collected": len(values)}
    )
