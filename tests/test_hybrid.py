"""Tests for the hybrid post-quantum signing layer.

Run with the post-quantum extra installed:

    pip install -r requirements-pqc.txt
    python3 -m pytest tests/test_hybrid.py -v
"""
import base64
import json
import os
import stat

import pytest

pytest.importorskip("pqcrypto", reason="the hybrid profile needs the pqcrypto extra")

from sel import pqc
from sel.canonical import digest
from sel.ledger import Ledger

pytestmark = pytest.mark.skipif(not pqc.PQC_AVAILABLE, reason=pqc.PQC_ERROR)


def make_ledger(tmp_path, n=6):
    signer = pqc.Signer(str(tmp_path / "keys"))
    led = Ledger(str(tmp_path / "ledger.jsonl"), signer=signer)
    led.add_key_record()
    for i in range(n):
        led.append(subject="SUBJ-%02d" % i, decision="ASSESSED", tier="HIGH")
    led.seal_checkpoint()
    return led, signer


def rewrite(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")


def rehash(records):
    """Rebuild the hash chain after an attacker edits the content."""
    prev = "0" * 64
    for i, rec in enumerate(records):
        rec["seq"] = i
        rec["prev_hash"] = prev
        rec.pop("hash", None)
        rec["hash"] = digest(rec)
        prev = rec["hash"]
    return records


def test_keys_are_private(tmp_path):
    pqc.Signer(str(tmp_path / "keys"))
    for name in ("ed25519.pem", "mldsa65.sk"):
        mode = stat.S_IMODE(os.stat(tmp_path / "keys" / name).st_mode)
        assert mode == 0o600, "%s is %o, not 0600" % (name, mode)


def test_fingerprint_is_stable(tmp_path):
    first = pqc.Signer(str(tmp_path / "keys")).fingerprint
    second = pqc.Signer(str(tmp_path / "keys")).fingerprint
    assert first == second
    assert len(first) == 16


def test_every_record_is_signed(tmp_path):
    led, _ = make_ledger(tmp_path)
    kinds = [r.get("kind") for r in led.all()]
    assert kinds[0] == pqc.KIND_KEY
    assert kinds.count(pqc.KIND_CHECKPOINT) == 1
    for rec in led.all():
        assert rec.get("sig"), "record %s has no ed25519 signature" % rec["seq"]
    assert led.all()[0].get("mldsa_sig"), "the KEY record has no ml-dsa signature"


def test_hybrid_profile_verifies(tmp_path):
    led, signer = make_ledger(tmp_path)
    res = led.verify_signatures()
    assert res["ok"], res["detail"]
    assert res["fingerprint"] == signer.fingerprint
    assert res["signed_records"] == 6
    assert res["checkpoints"] == 1
    assert res["unsealed_tail"] == 0


def test_content_tamper_breaks_chain_and_is_reported(tmp_path):
    led, _ = make_ledger(tmp_path)
    records = led.all()
    records[3]["tier"] = "LOW"
    rewrite(led.path, records)
    reopened = Ledger(led.path)
    ok, bad, _ = reopened.verify()
    assert not ok
    assert bad == 3


def test_forged_chain_without_signatures_is_refused(tmp_path):
    """The attack the hash chain alone cannot stop: rebuild everything, sign nothing."""
    led, _ = make_ledger(tmp_path)
    records = led.all()
    for rec in records:
        rec.pop("sig", None)
        rec.pop("mldsa_sig", None)
    records[3]["tier"] = "LOW"
    rewrite(led.path, rehash(records))
    reopened = Ledger(led.path)
    ok, _, _ = reopened.verify()
    assert ok, "an unsigned rebuild still re-hashes cleanly, which is the point"
    res = reopened.verify_signatures()
    assert not res["ok"]
    assert "signature" in res["detail"].lower()


def test_tampered_ed25519_signature_is_caught(tmp_path):
    led, _ = make_ledger(tmp_path)
    records = led.all()
    raw = list(base64.b64decode(records[3]["sig"]))
    raw[5] ^= 0x01
    records[3]["sig"] = base64.b64encode(bytes(raw)).decode()
    rewrite(led.path, rehash(records))
    res = Ledger(led.path).verify_signatures()
    assert not res["ok"]
    assert res["first_bad_seq"] == 3
    assert "ed25519" in res["detail"]


def test_tampered_mldsa_checkpoint_is_caught(tmp_path):
    led, _ = make_ledger(tmp_path)
    records = led.all()
    checkpoint = [r for r in records if r.get("kind") == pqc.KIND_CHECKPOINT][0]
    raw = list(base64.b64decode(checkpoint["mldsa_sig"]))
    raw[900] ^= 0x01
    checkpoint["mldsa_sig"] = base64.b64encode(bytes(raw)).decode()
    rewrite(led.path, rehash(records))
    res = Ledger(led.path).verify_signatures()
    assert not res["ok"]
    assert "ml-dsa" in res["detail"]


def test_checkpoint_gap_is_reported(tmp_path):
    led, _ = make_ledger(tmp_path)
    records = [r for r in led.all() if r.get("kind") != pqc.KIND_CHECKPOINT]
    rewrite(led.path, rehash(records))
    res = Ledger(led.path).verify_signatures()
    assert not res["ok"]
    assert "signature" in res["detail"].lower() or "checkpoint" in res["detail"].lower()


def test_pinned_fingerprint_is_enforced(tmp_path):
    led, _ = make_ledger(tmp_path)
    res = led.verify_signatures(expected_fingerprint="0" * 16)
    assert not res["ok"]
    assert "pinned" in res["detail"]


def test_unsigned_ledger_still_works_without_a_signer(tmp_path):
    led = Ledger(str(tmp_path / "plain.jsonl"))
    led.append(subject="SUBJ-00", decision="ASSESSED", tier="HIGH")
    ok, _, _ = led.verify()
    assert ok
    assert "sig" not in led.all()[0]
    res = led.verify_signatures()
    assert not res["ok"]
    assert "KEY record" in res["detail"]


def test_sizes_match_the_published_table(tmp_path):
    _, signer = make_ledger(tmp_path)
    assert len(signer.keys.ml_pub) == 1952
    assert len(signer.keys.ed_pub) == 32
    sig = signer.sign_checkpoint({"a": 1})[1]
    assert len(base64.b64decode(sig)) == 3309
