"""Build and verify a hybrid signed evidence ledger, and measure the cost.

    python3 -m sel.hybrid --data-dir data-hybrid --fresh
    python3 -m sel.hybrid --bench

The benchmark prints the table that docs/HYBRID-PQC.md carries, so the published
numbers can be reproduced on any machine that runs the same command.
"""
import argparse
import json
import os
import shutil
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import pqc
from .engine import Engine


def build(data_dir, fresh=False, keydir=None):
    if fresh and os.path.isdir(data_dir):
        shutil.rmtree(data_dir)
    signer = pqc.Signer(keydir or os.path.join(data_dir, "keys"))
    t0 = time.time()
    eng = Engine(data_dir, signer=signer)
    opened = time.time() - t0
    t1 = time.time()
    eng.run_cycle()
    cycle = time.time() - t1
    eng.ledger.seal_checkpoint()
    t2 = time.time()
    chain = eng.ledger.verify()
    chain_s = time.time() - t2
    t3 = time.time()
    sig = eng.ledger.verify_signatures()
    sig_s = time.time() - t3
    return {
        "data_dir": data_dir,
        "records": len(eng.ledger),
        "open_s": round(opened, 3),
        "cycle_s": round(cycle, 3),
        "chain_verify_s": round(chain_s, 3),
        "signature_verify_s": round(sig_s, 3),
        "chain_ok": chain[0],
        "chain_detail": chain[2],
        "signatures": sig,
        "fingerprint": signer.fingerprint,
        "suite": pqc.SUITE,
    }


def bench(rounds=30):
    msg = b'{"seq":5842,"tier":"HIGH","consent":"GRANTED","decision":"QUEUED"}'
    rows = []
    ed_sk = Ed25519PrivateKey.generate()
    ed_pk = ed_sk.public_key()
    for _ in range(3):
        ed_sk.sign(msg)
    t = time.time()
    for _ in range(rounds):
        ed_sig = ed_sk.sign(msg)
    ed_sign = (time.time() - t) / rounds * 1000
    t = time.time()
    for _ in range(rounds):
        ed_pk.verify(ed_sig, msg)
    ed_verify = (time.time() - t) / rounds * 1000
    rows.append(("Ed25519", len(ed_sig), 32, ed_sign, ed_verify))
    for name, mod, size in (
        ("ML-DSA-44", pqc._mldsa44, 0),
        ("ML-DSA-65", pqc._mldsa, 0),
        ("ML-DSA-87", pqc._mldsa87, 0),
    ):
        pk, sk = mod.keygen()
        for _ in range(3):
            mod.sign(sk, msg)
        t = time.time()
        for _ in range(rounds):
            sig = mod.sign(sk, msg)
        sign_ms = (time.time() - t) / rounds * 1000
        t = time.time()
        for _ in range(rounds):
            mod.verify(pk, msg, sig)
        verify_ms = (time.time() - t) / rounds * 1000
        rows.append((name, len(sig), len(pk), sign_ms, verify_ms))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hybrid post-quantum evidence profile")
    ap.add_argument("--data-dir", default="data-hybrid")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.bench:
        print("| algorithm | signature | public key | sign | verify |")
        print("| --- | --- | --- | --- | --- |")
        for name, s, pk, sm, vm in bench():
            print("| %s | %d B | %d B | %.2f ms | %.2f ms |" % (name, s, pk, sm, vm))
        return 0

    res = build(args.data_dir, fresh=args.fresh)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print("suite    :", res["suite"])
        print("key      :", res["fingerprint"])
        print("records  :", res["records"])
        print("cycle    : %.3f s" % res["cycle_s"])
        sig = res["signatures"]
        print("chain    :", "OK" if res["chain_ok"] else "BROKEN", "-", res["chain_detail"])
        print("sign     :", "OK" if sig["ok"] else "FAILED", "-", sig["detail"])
    return 0 if res["chain_ok"] and res["signatures"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
