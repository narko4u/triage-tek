"""Tamper harness.

Copies the ledger, edits exactly one field inside one record, and leaves the
original untouched. Run the verifier against the copy and it fails at that
record. This is how the demo proves the chain is actually doing something,
rather than asserting it.
"""
import argparse
import json
import shutil

from .ledger import Ledger


def tamper(src, dst, seq, field, value):
    shutil.copyfile(src, dst)
    with open(dst, "r", encoding="utf-8") as fh:
        rows = [json.loads(l) for l in fh if l.strip()]
    if seq >= len(rows):
        raise SystemExit("seq %d out of range (%d records)" % (seq, len(rows)))
    if value == rows[seq].get(field):
        # always produce a visible change, otherwise the test proves nothing
        value = "LOW" if rows[seq][field] != "LOW" else "HIGH"
    if field not in rows[seq]:
        raise SystemExit("field %r not on record %d" % (field, seq))
    before = rows[seq][field]
    rows[seq][field] = value
    with open(dst, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    return {"seq": seq, "field": field, "before": before, "after": value}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Tamper with a copy of the ledger")
    ap.add_argument("--ledger", default="data/ledger.jsonl")
    ap.add_argument("--out", default="data/tampered.jsonl")
    ap.add_argument("--seq", type=int, default=None,
                    help="record to edit; omit to pick the first high-tier assessment")
    ap.add_argument("--field", default="tier")
    ap.add_argument("--value", default="LOW")
    args = ap.parse_args(argv)

    seq = args.seq
    if seq is None:
        seq = 0
        with open(args.ledger, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if not line.strip():
                    continue
                r = json.loads(line)
                if r.get("tier") == "HIGH":
                    seq = i
                    break
    info = tamper(args.ledger, args.out, seq, args.field, args.value)
    print("tampered record", info["seq"], "field", info["field"], ":", info["before"], "->", info["after"])
    ok, bad, detail = Ledger(args.out).verify()
    print("verify tampered copy:", "OK (unexpected)" if ok else "BROKEN at seq %s — %s" % (bad, detail))
    return 0 if not ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
