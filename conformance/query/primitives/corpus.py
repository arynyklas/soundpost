# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Independent authored inputs, not a copied telemetry language corpus.

There are deliberately no guessed profile-dependent expected answers here.
The exact compiler + generic module execution supplies real observations.
Every regex case executes BOTH primitive callers, never an optimized selector.
"""
import base64


def b64(value):
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def cases():
    inputs = [
        ("kawi-letter", r"\p{L}", "\U00011f04"),
        ("kawi-script", r"\p{Kawi}", "\U00011f04"),
        ("garay-letter", r"\p{L}", "\U00010d50"),
        ("garay-script", r"\p{Garay}", "\U00010d50"),
        ("taiyo-letter", r"\p{L}", "\U0001e6c0"),
        ("taiyo-script", r"\p{Tai_Yo}", "\U0001e6c0"),
        ("garay-not-letter", r"\P{L}", "\U00010d50"),
        ("cn-garay", r"\p{Cn}", "\U00010d50"),
        ("cn-kawi", r"\p{Cn}", "\U00011f04"),
        ("lc-latin", r"\p{LC}", "A"),
        ("alias-letter", r"\p{Letter}", "\U00011f04"),
        ("alias-greek", r"\p{greek}", "σ"),
        ("canonical-greek", r"\p{Greek}", "σ"),
        ("alias-assigned", r"\p{Assigned}", "\U00010d50"),
        ("alias-ascii", r"\p{ASCII}", "A"),
        ("alias-ascii-nonascii", r"\p{ASCII}", "é"),
        ("fold-a7cb", r"(?i)\x{a7cb}", "\u0264"),
        ("fold-garay", r"(?i)\x{10d50}", "\U00010d70"),
        ("fold-kelvin", "(?i)k", "K"),
        ("fold-longs", "(?i)s", "ſ"),
        ("fold-sigma", "(?i)σ", "ς"),
        ("ascii-posix", "[[:alpha:]]", "é"),
        ("ascii-perl", r"\w", "é"),
        ("no-normalization", "é", "e\u0301"),
        ("lookahead", "(?=x)", "x"),
        ("backreference", r"(x)\1", "xx"),
        ("repeat-over-limit", "a{1001}", "a"),
        ("repeat-limit", "a{1000}", "a" * 1000),
        ("invalid-range", "[z-a]", "a"),
        ("invalid-pattern-utf8", b"\xff", ""),
        ("invalid-input-utf8", "^.$", b"\xff"),
        ("invalid-two-input-utf8", "^..$", b"\xff\xfe"),
        ("invalid-overlong-utf8", ".", b"\xc0\xaf"),
        ("replacement-rune-input", "�", b"\xffx"),
        ("newline", "a.b", "a\nb"),
        ("search-substring", "a.b", "xaZby"),
        ("explicit-dotnl-off", "(?-s:a.b)", "a\nb"),
        ("explicit-dotnl-on", "(?s:a.b)", "a\nb"),
        ("multiline", "(?m)^b$", "a\nb\nc"),
        ("dollar-before-newline", "a$", "a\n"),
        ("absolute", r"\Aa\z", "a\n"),
        ("word-boundary", r"\b.", "é a"),
        ("capture-optional", r"(?P<word>a)(b)?", "za"),
        ("capture-replacement", r"(?P<word>a)(b)?", "a ab"),
        ("leftmost-first", "(a|ab)(b)?", "ab"),
        ("empty-adjacent", "a*", "ba"),
        ("empty-unicode", "", "éx"),
        ("empty-invalid", "", b"\xff\xfe"),
        ("empty-anchors", r"\A|$", "ab"),
        ("empty-input", "a*", ""),
    ]
    out = []
    for name, pattern, text in inputs:
        for mode in ("search", "label"):
            out.append({"id": name + "/" + mode, "operation": "regex", "mode": mode,
                        "pattern_b64": b64(pattern), "input_b64": b64(text),
                        "replacement": "[${word}:$2:$0:$$]", "limit": -1})
    for limit in (0, 1, 2):
        out.append({"id": "empty-progression-limit-" + str(limit), "operation": "regex",
                    "mode": "search", "pattern_b64": b64("a*"), "input_b64": b64("ba é"),
                    "replacement": "x", "limit": limit})
    out.append({"id": "case/upper-lower-fold", "operation": "case",
                "input_b64": b64("KkKSsſΣσς\ua7cb\u0264\U00010d50\U00010d70\U00011f04\U0001e6c0İıßé"),
                "runes": [ord(c) for c in "KkKSsſΣσς\ua7cb\u0264\U00010d50\U00010d70\U00011f04\U0001e6c0"]})
    out.append({"id": "case/invalid-utf8", "operation": "case", "input_b64": b64(b"\xffK\xfe"), "runes": []})
    return out
