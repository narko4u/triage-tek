"""Rebuild a ledger the way an attacker with write access would.

Take the records, strip every signature, recompute every hash from genesis, and
write a file that re-hashes cleanly. Against a bare hash chain this forgery is
undetectable. Against the hybrid profile it fails at the first record, because
the attacker does not hold the signing keys.

    python3 -m sel.forge --ledger data/ledger.jsonl --out data/forged.jsonl
"""
import argparse
import json
import sys

from .canonical import digest, dumps
from .ledger import GENESIS, Ledger


def forge(records, field=None, value=None):
    out = []
    prev = GENESIS
    edited = False
    for i, original in enumerate(records):
        rec = dict(original)
        rec.pop("sig", None)
        rec.pop("mldsa_sig", None)
        if field and not edited and field in rec and rec.get("kind") is None:
            rec[field] = value
            edited = True
        rec["seq"] = i
        rec["prev_hash"] = prev
        rec.pop("hash", None)
        rec["hash"] = digest(rec)
        prev = rec["hash"]
        out.append(rec)
    return out, edited


def main(argv=None):
    ap = argparse.ArgumentParser(description="Rebuild a ledger without signatures")
    ap.add_argument("--ledger", default="data/ledger.jsonl")
    ap.add_argument("--out", default="data/forged.jsonl")
    ap.add_argument("--field", default=None, help="field to edit in the first record that has it")
    ap.add_argument("--value", default=None, help="replacement value for --field")
    args = ap.parse_args(argv)

    records = Ledger(args.ledger).all()
    forged, edited = forge(records, args.field, args.value)
    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in forged:
            fh.write(dumps(rec) + "\n")
    print("wrote", args.out)
    print("records:", len(forged))
    print("edited :", args.field, "->", args.value if edited else "nothing edited")
    print("note   : every hash recomputed from genesis, every signature removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
