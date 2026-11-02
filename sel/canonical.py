"""Canonical JSON encoding used by every hash in this project.

Rules: sorted keys, no insignificant whitespace, UTF-8, no NaN/Infinity.
Anything that gets hashed goes through dumps() so the digest is reproducible
on any machine and in any language that follows the same rules.
"""
import hashlib
import json


def dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(obj):
    return hashlib.sha256(dumps(obj).encode("utf-8")).hexdigest()
