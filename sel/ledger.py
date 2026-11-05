"""Append-only, hash-chained evidence ledger.

Each record is sealed over its own content plus the previous record's hash.
Editing, inserting or deleting a record breaks the chain at that index, which
is what the verifier reports. This is tamper-EVIDENT, not tamper-proof: an
attacker with write access to the file can rewrite the whole chain from the
tamper point onwards. See docs/LIMITATIONS.md, which says so plainly.
"""
import json
import math
import os
import threading
from datetime import datetime, timezone

from . import pqc
from .canonical import digest, dumps

GENESIS = "0" * 64


class LedgerFormatError(ValueError):
    """The file on disk is not a ledger this reader can verify.

    Raised with the line number so a corrupt or truncated file fails loudly
    instead of being read as a shorter, still-valid chain.
    """

    def __init__(self, message, line=None):
        super().__init__(message)
        self.line = line


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _reject_nonfinite(value, lineno, path="record"):
    """JSON allows NaN and Infinity by default; evidence does not."""
    if isinstance(value, float) and not math.isfinite(value):
        raise LedgerFormatError(
            "line %d has a non-finite number at %s" % (lineno, path), lineno
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_nonfinite(item, lineno, "%s.%s" % (path, key))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _reject_nonfinite(item, lineno, "%s[%d]" % (path, i))

class Ledger:
    def __init__(self, path, signer=None):
        self.path = path
        self.signer = signer
        self._lock = threading.Lock()
        self._records = []
        self._covered_to = -1
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                raw = fh.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LedgerFormatError(
                    "the ledger is not valid UTF-8: %s" % exc
                ) from exc
            for lineno, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LedgerFormatError(
                        "line %d is not valid JSON: %s" % (lineno, exc.msg), lineno
                    ) from exc
                self._check_shape(rec, lineno)
                self._records.append(rec)
        for rec in self._records:
            if rec.get("kind") == pqc.KIND_CHECKPOINT:
                self._covered_to = max(self._covered_to, int(rec.get("to_seq", -1)))

    @staticmethod
    def _check_shape(rec, lineno):
        """A parsed line must be a record, not just any JSON value."""
        if not isinstance(rec, dict):
            raise LedgerFormatError("line %d is not a JSON object" % lineno, lineno)
        seq = rec.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise LedgerFormatError("line %d has no valid seq" % lineno, lineno)
        digest_value = rec.get("hash")
        if not isinstance(digest_value, str) or len(digest_value) != 64:
            raise LedgerFormatError("line %d has no valid hash" % lineno, lineno)
        if not isinstance(rec.get("prev_hash"), str):
            raise LedgerFormatError("line %d has no prev_hash" % lineno, lineno)
        if rec.get("kind") == pqc.KIND_CHECKPOINT:
            for field in ("from_seq", "to_seq"):
                value = rec.get(field)
                if not isinstance(value, int) or isinstance(value, bool):
                    raise LedgerFormatError(
                        "line %d checkpoint has no valid %s" % (lineno, field), lineno
                    )
            if rec["from_seq"] < 0 or rec["to_seq"] < rec["from_seq"]:
                raise LedgerFormatError(
                    "line %d checkpoint range is inverted" % lineno, lineno
                )
        if rec.get("kind") == pqc.KIND_KEY:
            for field in ("ed25519_pub", "mldsa65_pub"):
                value = rec.get(field)
                if not isinstance(value, str) or not value:
                    raise LedgerFormatError(
                        "line %d key record has no valid %s" % (lineno, field), lineno
                    )
            try:
                bytes.fromhex(rec["ed25519_pub"])
            except ValueError:
                raise LedgerFormatError(
                    "line %d key record public key is not hex" % lineno, lineno
                ) from None
        _reject_nonfinite(rec, lineno)


    # ---- reading -------------------------------------------------------
    def __len__(self):
        return len(self._records)

    def all(self):
        return list(self._records)

    @property
    def head(self):
        return self._records[-1]["hash"] if self._records else GENESIS

    def find(self, subject=None, decision=None):
        out = []
        for r in self._records:
            if r.get("kind") in (pqc.KIND_KEY, pqc.KIND_CHECKPOINT):
                continue
            if subject and r.get("subject") != subject:
                continue
            if decision and r.get("decision") != decision:
                continue
            out.append(r)
        return out

    # ---- writing -------------------------------------------------------
    def flush(self):
        """Force durability once, instead of once per record."""
        if os.path.exists(self.path):
            with open(self.path, "rb") as fh:
                os.fsync(fh.fileno())

    def append(self, _fsync=True, **fields):
        with self._lock:
            return self._append_locked(_fsync, fields)

    def add_key_record(self):
        """Seal the public signing material as the first signed record."""
        if self.signer is None:
            raise RuntimeError("this ledger has no signer")
        with self._lock:
            if self._records:
                raise RuntimeError("the key record must be the first record")
            body = {"seq": 0, "prev_hash": GENESIS, "sealed_at": utc_now(),
                    "kind": pqc.KIND_KEY}
            body.update(self.signer.key_record_fields())
            ed_sig, ml_sig = self.signer.sign_checkpoint(body)
            body["sig"] = ed_sig
            body["mldsa_sig"] = ml_sig
            return self._write_locked(body, _fsync=True, checkpoint=False)

    def _append_locked(self, _fsync, fields):
        body = {"seq": len(self._records), "prev_hash": self.head, "sealed_at": utc_now()}
        body.update(fields)
        if self.signer is not None:
            body["sig"] = self.signer.sign_record(body)
        return self._write_locked(body, _fsync)

    def _write_locked(self, body, _fsync=True, checkpoint=True):
        record = dict(body)
        record["hash"] = digest(record)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(dumps(record) + "\n")
            fh.flush()
            if _fsync:
                os.fsync(fh.fileno())
        self._records.append(record)
        if (checkpoint and self.signer is not None
                and len(self._records) % pqc.CHECKPOINT_EVERY == 0):
            self._append_checkpoint_locked()
        return record

    def _append_checkpoint_locked(self):
        from_seq = self._covered_to + 1
        to_seq = len(self._records) - 1
        segment = [r["hash"] for r in self._records[from_seq:to_seq + 1]]
        body = {
            "seq": len(self._records),
            "prev_hash": self.head,
            "sealed_at": utc_now(),
            "kind": pqc.KIND_CHECKPOINT,
            "from_seq": from_seq,
            "to_seq": to_seq,
            "merkle_root": pqc.merkle_root(segment),
            "suite": pqc.SUITE,
            "fingerprint": self.signer.fingerprint,
        }
        ed_sig, ml_sig = self.signer.sign_checkpoint(body)
        body["sig"] = ed_sig
        body["mldsa_sig"] = ml_sig
        self._covered_to = to_seq
        return self._write_locked(body, _fsync=True, checkpoint=False)

    def seal_checkpoint(self):
        """Seal a checkpoint now, covering any records since the last one."""
        with self._lock:
            if self.signer is None or self._covered_to == len(self._records) - 1:
                return None
            return self._append_checkpoint_locked()

    def verify_signatures(self, expected_fingerprint=None):
        """Verify the hybrid signature layer. Returns a result dict."""
        return pqc.verify_ledger(self._records, expected_fingerprint)

    # ---- verification --------------------------------------------------
    def verify(self):
        """Recompute the chain. Returns (ok, first_bad_seq, detail)."""
        prev = GENESIS
        for i, rec in enumerate(self._records):
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("seq") != i:
                return False, i, "sequence number out of order"
            if rec.get("prev_hash") != prev:
                return False, i, "prev_hash does not match the record before it"
            if digest(body) != rec.get("hash"):
                return False, i, "record content does not match its own hash"
            prev = rec["hash"]
        return True, None, "chain intact across %d records" % len(self._records)
