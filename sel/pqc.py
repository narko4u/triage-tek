"""Hybrid post-quantum signing layer for the screening evidence ledger.

Two independent signatures per sealed artefact:

  * Ed25519 on every record. 64 byte signature, cheap enough to sign per record.
  * ML-DSA-65 (FIPS 204) over a Merkle root per checkpoint, every 250 records.

Neither half carries the evidence alone. The verifier requires both, so a break
in either algorithm leaves the other one standing. See docs/HYBRID-PQC.md.
"""
import base64
import hashlib
import os
import stat

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    ED25519_AVAILABLE = True
    ED25519_ERROR = ""
except Exception as exc:  # the default profile must run with no dependencies
    serialization = Ed25519PrivateKey = Ed25519PublicKey = None
    ED25519_AVAILABLE = False
    ED25519_ERROR = "%s: %s" % (type(exc).__name__, exc)

from .canonical import dumps

SUITE = "hybrid-ed25519-mldsa65-v1"
CHECKPOINT_EVERY = 250
KIND_KEY = "KEY"
KIND_CHECKPOINT = "CHECKPOINT"

try:  # post-quantum half is optional at import time, never at verify time
    from pqcrypto.sign import ml_dsa_44 as _mldsa44
    from pqcrypto.sign import ml_dsa_65 as _mldsa
    from pqcrypto.sign import ml_dsa_87 as _mldsa87
    PQC_AVAILABLE = True
    PQC_ERROR = ""
except Exception as exc:  # pragma: no cover - exercised by the skip path
    _mldsa = _mldsa44 = _mldsa87 = None
    PQC_AVAILABLE = False
    PQC_ERROR = "%s: %s" % (type(exc).__name__, exc)


class PQCUnavailable(RuntimeError):
    """Raised when the hybrid profile is requested but ML-DSA cannot load."""


def require_pqc():
    if not ED25519_AVAILABLE:
        raise PQCUnavailable(
            "the hybrid profile needs the cryptography package for Ed25519. "
            "Install it with: pip install -r requirements-pqc.txt (%s)" % ED25519_ERROR
        )
    if not PQC_AVAILABLE:
        raise PQCUnavailable(
            "the hybrid profile needs the pqcrypto package for ML-DSA-65. "
            "Install it with: pip install -r requirements-pqc.txt (%s)" % PQC_ERROR
        )


def _canonical_bytes(obj):
    return dumps(obj).encode("utf-8")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(text.encode("ascii"))


def merkle_root(record_hashes):
    """Binary Merkle root over the hex hashes of a segment, odd node promoted."""
    if not record_hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(h) for h in record_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


class Keys:
    """Long-lived signing keys for one screening environment.

    Private material lives in a 0600 file outside git. The public half is
    published inside the ledger as a signed KEY record, and its fingerprint is
    what an external party pins when they want to trust more than the file.
    """

    def __init__(self, keydir):
        require_pqc()
        self.keydir = keydir
        os.makedirs(keydir, exist_ok=True)
        self._ed_path = os.path.join(keydir, "ed25519.pem")
        self._ml_pk_path = os.path.join(keydir, "mldsa65.pk")
        self._ml_sk_path = os.path.join(keydir, "mldsa65.sk")
        if os.path.exists(self._ed_path):
            self._load()
        else:
            self._create()

    # ---- key lifecycle -------------------------------------------------
    def _write_private(self, path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def _create(self):
        ed_sk = Ed25519PrivateKey.generate()
        self._write_private(
            self._ed_path,
            ed_sk.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        ml_pk, ml_sk = _mldsa.keygen()
        self._write_private(self._ml_pk_path, ml_pk)
        self._write_private(self._ml_sk_path, ml_sk)
        self._load()

    def _load(self):
        with open(self._ed_path, "rb") as fh:
            self.ed_sk = serialization.load_pem_private_key(fh.read(), password=None)
        self.ed_pk = self.ed_sk.public_key()
        self.ed_pub = self.ed_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        with open(self._ml_pk_path, "rb") as fh:
            self.ml_pub = fh.read()
        with open(self._ml_sk_path, "rb") as fh:
            self.ml_sk = fh.read()

    @property
    def fingerprint(self):
        return hashlib.sha256(self.ed_pub + self.ml_pub).hexdigest()[:16]

    def public_material(self):
        return {
            "suite": SUITE,
            "ed25519_pub": self.ed_pub.hex(),
            "mldsa65_pub": self.ml_pub.hex(),
            "fingerprint": self.fingerprint,
        }


class Signer:
    """Wraps Keys with the two signing operations the ledger needs."""

    def __init__(self, keydir):
        self.keys = Keys(keydir)

    @property
    def fingerprint(self):
        return self.keys.fingerprint

    def key_record_fields(self):
        return self.keys.public_material()

    def sign_record(self, body):
        """Ed25519 over the canonical record body, returned base64."""
        return _b64(self.keys.ed_sk.sign(_canonical_bytes(body)))

    def sign_checkpoint(self, body):
        """Both halves over the canonical checkpoint body."""
        payload = _canonical_bytes(body)
        return _b64(self.keys.ed_sk.sign(payload)), _b64(_mldsa.sign(self.keys.ml_sk, payload))


def verify_record(ed_pub, body, sig_b64):
    if not ED25519_AVAILABLE:
        return False, "ed25519 support is not installed"
    try:
        Ed25519PublicKey.from_public_bytes(ed_pub).verify(_unb64(sig_b64), _canonical_bytes(body))
        return True, ""
    except Exception as exc:
        return False, "ed25519 signature does not verify (%s)" % type(exc).__name__


def verify_checkpoint(pub, body, sig_b64, mldsa_sig_b64):
    """Both halves must pass. Returns (ok, failures)."""
    failures = []
    if not (ED25519_AVAILABLE and PQC_AVAILABLE):
        return False, ["signature libraries are not installed"]
    payload = _canonical_bytes(body)
    try:
        Ed25519PublicKey.from_public_bytes(pub["ed25519_pub"]).verify(
            _unb64(sig_b64), payload
        )
    except Exception as exc:
        failures.append("ed25519 half failed (%s)" % type(exc).__name__)
    try:
        _mldsa.verify(pub["mldsa65_pub"], payload, _unb64(mldsa_sig_b64))
    except Exception:
        failures.append("ml-dsa half failed")
    return (not failures), failures


def record_body(rec):
    """The part of a record that gets signed, before hash and signatures."""
    return {k: v for k, v in rec.items() if k not in ("hash", "sig", "mldsa_sig")}


def verify_ledger(records, expected_fingerprint=None, require_hybrid=True):
    """Verify both signature halves across a whole ledger.

    Returns a dict: ok, first_bad_seq, detail, fingerprint, signed_records,
    checkpoints, unsealed_tail.
    """
    out = {
        "ok": False,
        "first_bad_seq": None,
        "detail": "",
        "fingerprint": None,
        "signed_records": 0,
        "checkpoints": 0,
        "unsealed_tail": 0,
    }
    keys = [r for r in records if r.get("kind") == KIND_KEY]
    if not keys:
        out["detail"] = "no signed KEY record in the ledger"
        out["first_bad_seq"] = 0 if records else None
        return out
    if len(keys) > 1:
        out["detail"] = "more than one KEY record"
        out["first_bad_seq"] = keys[1].get("seq")
        return out
    key = keys[0]
    try:
        pub = {
            "ed25519_pub": bytes.fromhex(key.get("ed25519_pub", "")),
            "mldsa65_pub": bytes.fromhex(key.get("mldsa65_pub", "")),
        }
    except ValueError:
        out["first_bad_seq"] = key.get("seq")
        out["detail"] = "KEY record carries malformed public key material"
        return out
    out["fingerprint"] = key.get("fingerprint")
    out["detail"] = "suite %s" % key.get("suite")
    if expected_fingerprint and key.get("fingerprint") != expected_fingerprint:
        out["first_bad_seq"] = key.get("seq")
        out["detail"] = "key fingerprint %s does not match the pinned %s" % (
            key.get("fingerprint"),
            expected_fingerprint,
        )
        return out
    if not key.get("sig") or not key.get("mldsa_sig"):
        out["first_bad_seq"] = key.get("seq")
        out["detail"] = "the KEY record carries no signature, so nothing in this ledger can be trusted"
        return out
    ok, failures = verify_checkpoint(pub, record_body(key), key.get("sig", ""), key.get("mldsa_sig", ""))
    if not ok:
        out["first_bad_seq"] = key.get("seq")
        out["detail"] = "KEY record: " + ", ".join(failures)
        return out
    for rec in records:
        seq = rec.get("seq")
        kind = rec.get("kind")
        if kind in (KIND_KEY, KIND_CHECKPOINT):
            continue
        if not rec.get("sig"):
            if require_hybrid:
                out["first_bad_seq"] = seq
                out["detail"] = "record carries no signature"
                return out
            continue
        good, why = verify_record(pub["ed25519_pub"], record_body(rec), rec["sig"])
        if not good:
            out["first_bad_seq"] = seq
            out["detail"] = why
            return out
        out["signed_records"] += 1
    covers_to = -1
    for rec in [r for r in records if r.get("kind") == KIND_CHECKPOINT]:
        seq = rec.get("seq")
        body = record_body(rec)
        if body.get("from_seq") != covers_to + 1:
            out["first_bad_seq"] = seq
            out["detail"] = "checkpoint coverage starts at %s, expected %s" % (
                body.get("from_seq"),
                covers_to + 1,
            )
            return out
        segment = [r["hash"] for r in records if body["from_seq"] <= r.get("seq") <= body["to_seq"]]
        if merkle_root(segment) != body.get("merkle_root"):
            out["first_bad_seq"] = seq
            out["detail"] = "merkle root does not match the records it covers"
            return out
        good, failures = verify_checkpoint(pub, body, rec.get("sig", ""), rec.get("mldsa_sig", ""))
        if not good:
            out["first_bad_seq"] = seq
            out["detail"] = "checkpoint " + ", ".join(failures)
            return out
        covers_to = body["to_seq"]
        out["checkpoints"] += 1
    if out["checkpoints"] == 0:
        out["first_bad_seq"] = 0 if records else None
        out["detail"] = "no ML-DSA checkpoint covers the ledger"
        return out
    uncovered = [
        r for r in records
        if r.get("seq", -1) > covers_to and r.get("kind") != KIND_CHECKPOINT
    ]
    out["unsealed_tail"] = len(uncovered)
    if out["unsealed_tail"]:
        out["first_bad_seq"] = uncovered[0].get("seq")
        out["detail"] = "%d records are not yet covered by an ML-DSA checkpoint" % out["unsealed_tail"]
        return out
    out["ok"] = True
    out["detail"] = "both signature halves verify across %d records in %d checkpoints" % (
        out["signed_records"],
        out["checkpoints"],
    )
    return out
