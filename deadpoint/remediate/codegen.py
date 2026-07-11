"""Patch codegen for STAGE 3 - REMEDIATE.

Given a source snippet, find weak ``random`` usages and emit a suggested unified
diff that swaps them for the CSPRNG equivalents from :mod:`.mappings`.
"""

from __future__ import annotations

import difflib
import re

from .mappings import BY_CALL

# Ordered so more specific patterns win (token/key before bare calls).
_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"random\.seed\s*\(\s*int\s*\(\s*time\.time\(\)\s*\)\s*\)"),
     "# SECURITY: do not seed a CSPRNG; remove this line and use secrets/os.urandom"),
    (re.compile(r"random\.randint\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)"),
     r"(\1 + secrets.randbelow((\2) - (\1) + 1))"),
    (re.compile(r"random\.randrange\s*\(\s*([^)]+?)\s*\)"),
     r"secrets.randbelow(\1)"),
    (re.compile(r"random\.choice\s*\("),
     "secrets.choice("),
    (re.compile(r"random\.getrandbits\s*\(\s*([^)]+?)\s*\)"),
     r"int.from_bytes(os.urandom(((\1) + 7) // 8), 'big')"),
    (re.compile(r"random\.random\s*\(\s*\)"),
     "(secrets.randbelow(1 << 53) / (1 << 53))"),
]


def scan(source: str) -> list[dict]:
    """Return a list of weak-usage findings with line numbers."""
    findings = []
    for lineno, line in enumerate(source.splitlines(), 1):
        for call, mapping in BY_CALL.items():
            if re.search(rf"random\.{re.escape(call)}\b", line) or (
                call in ("token", "key") and re.search(rf"\b{call}\b.*random\.", line)
            ):
                findings.append(
                    {"line": lineno, "text": line.strip(), "call": call,
                     "fix": mapping.secure, "why": mapping.why}
                )
                break
    return findings


def rewrite(source: str) -> str:
    """Apply the mechanical replacements to a snippet."""
    out_lines = []
    needs_secrets = needs_os = False
    for line in source.splitlines():
        new = line
        for pat, repl in _RULES:
            if pat.search(new):
                new = pat.sub(repl, new)
                if "secrets." in repl:
                    needs_secrets = True
                if "os.urandom" in repl:
                    needs_os = True
        out_lines.append(new)
    header = []
    if needs_secrets:
        header.append("import secrets")
    if needs_os:
        header.append("import os")
    body = "\n".join(out_lines)
    if header:
        body = "\n".join(header) + "\n" + body
    return body


def diff(source: str, filename: str = "snippet.py") -> str:
    """Return a unified diff patching the weak usages in ``source``."""
    fixed = rewrite(source)
    if fixed == source:
        return ""
    return "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
    )
