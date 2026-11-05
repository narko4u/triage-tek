"""Verify the evidence chain, hash links first, then both signature halves.

Exit code 0 means every record re-hashes to itself, links to its predecessor,
carries a valid Ed25519 signature and is covered by a valid ML-DSA-65
checkpoint. Exit code 1 means something failed, and the first bad index is
printed together with which half failed.
"""
import argparse
import json
import sys

from .ledger import Ledger, LedgerFormatError


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a screening evidence ledger")
    ap.add_argument("--ledger", default="data/ledger.jsonl")
    ap.add_argument("--fingerprint", default=None,
                    help="pin the signing key fingerprint expected in the KEY record")
    ap.add_argument("--expect-head", default=None,
                    help="pin the head hash out of band; catches truncation of the tail")
    ap.add_argument("--chain-only", action="store_true",
                    help="verify the hash chain and skip the signature layer")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        led = Ledger(args.ledger)
    except LedgerFormatError as exc:
        result = {
            "ok": False,
            "records": None,
            "head": None,
            "first_bad_seq": exc.line,
            "detail": str(exc),
            "signatures": None,
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("chain   : BROKEN -", exc)
        return 1

    ok, bad, detail = led.verify()
    if ok and args.expect_head and led.head != args.expect_head:
        ok, bad = False, None
        detail = "head %s does not match the pinned head %s" % (led.head, args.expect_head)
    result = {
        "ok": ok,
        "records": len(led),
        "head": led.head,
        "first_bad_seq": bad,
        "detail": detail,
        "signatures": None,
    }
    if ok and not args.chain_only:
        sig = led.verify_signatures(args.fingerprint)
        result["signatures"] = sig
        result["ok"] = ok and sig["ok"]

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("records :", len(led))
        print("head    :", led.head)
        if ok:
            print("chain   : OK -", detail)
        elif bad is None:
            print("chain   : BROKEN -", detail)
        else:
            print("chain   : BROKEN at seq", bad, "-", detail)
        sig = result["signatures"]
        if sig is not None:
            print("key     :", sig["fingerprint"])
            if sig["ok"]:
                print("sign    : OK -", sig["detail"])
                print("sealed  :", sig["signed_records"], "records,", sig["checkpoints"],
                      "checkpoints, unsealed tail", sig["unsealed_tail"])
            else:
                print("sign    : FAILED at seq", sig["first_bad_seq"], "-", sig["detail"])
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
