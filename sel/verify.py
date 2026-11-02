"""Verify the evidence chain.

Exit code 0 means every record re-hashes to itself and links to its predecessor.
Exit code 1 means the chain is broken, and the first bad index is printed.
"""
import argparse
import json
import sys

from .ledger import Ledger


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a screening evidence ledger")
    ap.add_argument("--ledger", default="data/ledger.jsonl")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    led = Ledger(args.ledger)
    ok, bad, detail = led.verify()
    result = {
        "ok": ok,
        "records": len(led),
        "head": led.head,
        "first_bad_seq": bad,
        "detail": detail,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("records :", len(led))
        print("head    :", led.head)
        if ok:
            print("result  : CHAIN OK —", detail)
        else:
            print("result  : CHAIN BROKEN at seq", bad, "—", detail)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
