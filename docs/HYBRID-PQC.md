# Hybrid post-quantum evidence

TriageTek seals every screening decision into a hash chain. A hash chain proves that a
record was not edited in place. It does not prove who wrote it: anyone with write access can
recompute the whole chain and produce a file that re-hashes cleanly from genesis.

The hybrid profile closes that gap with two independent signatures over every sealed record,
one classical and one post-quantum, and the verifier requires both.

## Why a screening record needs this

A screening decision is kept for the life of the person it concerns. National programmes work
to retention periods measured in decades, and records are read years after they are written,
by auditors who were never in the room.

That creates two problems a hash chain cannot answer.

1. **Forgery later.** A record that only carries a hash can be rebuilt by anyone who can write
   the file. A record that carries a signature can only be rebuilt by the holder of the key.
2. **Forgery by a machine that does not exist yet.** A signature made in 2026 must still mean
   something in 2046. Classical signatures are expected to fall to a cryptographically
   relevant quantum computer inside that window. Post-quantum signatures are expected to hold,
   but they are new, and new is exactly why they should not be trusted alone.

Hybrid answers both. If either algorithm falls, the other still stands, and the evidence does
not need to be re-signed to survive the transition.

## The design

Two levels, because per-record ML-DSA is honest but slow.

| Level | Algorithm | Covers | Signature |
| --- | --- | --- | --- |
| Every record | Ed25519 | the record body | 64 B |
| Every 250 records | ML-DSA-65 (FIPS 204) | a Merkle root over that segment | 3,309 B |

The Ed25519 signature is cheap enough to run on every transition. The ML-DSA signature binds a
whole segment at once through its Merkle root, so every record in that segment inherits the
post-quantum guarantee transitively. Twenty four checkpoints cover 5,841 records, which is
0.2 s of post-quantum signing instead of 51 s.

Both halves sign a canonical JSON body (sorted keys, no whitespace) so that the bytes signed
are the bytes verified. The record hash covers the signatures as well, so removing a signature
also breaks the hash.

## Measured on this build

Primitives, 30 rounds each on the build machine:

| algorithm | signature | public key | sign | verify |
| --- | --- | --- | --- | --- |
| Ed25519 | 64 B | 32 B | 0.03 ms | 0.11 ms |
| ML-DSA-44 | 2,420 B | 1,312 B | 6.27 ms | 0.12 ms |
| ML-DSA-65 | 3,309 B | 1,952 B | 10.17 ms | 0.18 ms |
| ML-DSA-87 | 4,627 B | 2,592 B | 11.44 ms | 0.29 ms |

The same commands on the machine that built this document:

- unsigned cycle, 5,841 records: 0.354 s
- hybrid cycle, 5,841 records plus 25 checkpoints and one key record: 0.716 s
- chain verification across 5,867 records: passed
- hybrid verification: `both signature halves verify across 5,841 records in 25 checkpoints`
- forged copy with every signature stripped and every hash recomputed: chain `OK`, signatures
  `FAILED at seq 0`

The overhead is 0.36 s for the full cohort, which is 0.06 ms per record. Reproduce all of it
with `python3 -m sel.hybrid --bench` and `python3 -m sel.hybrid --fresh`.

## What it proves, and what it does not

**Proves.** Every record was signed by the holder of the private key, and every segment was
bound into a post-quantum signed root. A rewrite of the file fails at the first record whose
signature does not verify, and the verifier says which half failed.

**Does not prove.** Who holds the key. The KEY record inside the ledger is self signed, so on
its own it only tells you the file is internally consistent. To trust a ledger beyond that,
pin the fingerprint out of band (`--fingerprint`), which is the same discipline as pinning a
certificate. The prototype prints `key` on every verification for exactly that reason.

**Does not prove.** That the person described is real, that consent was valid, or that the
clinician was honest. Signatures bind bytes to a key. Everything before that is governance.

**Not a substitute for anchoring.** Publishing the head hash somewhere the writer does not
control is still the answer to "was this the head at that time". Signing and anchoring solve
different halves of the problem and both belong in production.

## Run it

```bash
pip install -r requirements-pqc.txt
python3 -m sel.hybrid --data-dir data-hybrid --fresh
python3 -m sel.verify --ledger data-hybrid/ledger.jsonl
python3 -m sel.verify --ledger data-hybrid/ledger.jsonl --fingerprint <16 hex chars>
python3 -m sel.forge --ledger data-hybrid/ledger.jsonl --out data-hybrid/forged.jsonl --field tier --value LOW
python3 -m sel.verify --ledger data-hybrid/forged.jsonl   # exits 1, names the failure
python3 -m sel.hybrid --bench
```

Without the extra installed, the unsigned profile still runs and the default quick start is
unchanged. The hybrid commands say what is missing instead of failing somewhere deep.

## References

- FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA)
- FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- FIPS 205, Stateless Hash-Based Digital Signature Standard (SLH-DSA)
- RFC 8032, Ed25519
