"""Append-only, hash-chained evidence ledger.

Each record is sealed over its own content plus the previous record's hash.
Editing, inserting or deleting a record breaks the chain at that index, which
is what the verifier reports. This is tamper-EVIDENT, not tamper-proof: an
attacker with write access to the file can rewrite the whole chain from the
tamper point onwards. See docs/LIMITATIONS.md, which says so plainly.
"""
import json
import os
import threading
from datetime import datetime, timezone

from .canonical import digest, dumps

GENESIS = "0" * 64


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Ledger:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._records = []
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._records.append(json.loads(line))

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
            seq = len(self._records)
            record = {
                "seq": seq,
                "prev_hash": self.head,
                "sealed_at": utc_now(),
            }
            record.update(fields)
            record["hash"] = digest(record)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(dumps(record) + "\n")
                fh.flush()
                if _fsync:
                    os.fsync(fh.fileno())
            self._records.append(record)
            return record

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
