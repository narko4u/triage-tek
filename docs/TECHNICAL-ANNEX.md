# TriageTek: technical annex

How the prototype is built, for engineering reviewers.

The application form answers are written in plain English. This document is the build: the data
model, the state machine, the verification algorithm and the test matrix, with the numbers
measured on this tree.

- **Repository:** `github.com/narko4u/triage-tek`
- **Tree:** `84458a1` on `main`, identical to `origin/main` at `5cc98e5`
- **Runtime:** Python 3.11+, standard library only for the default profile
- **Optional extra:** `cryptography==50.0.2`, `pqcrypto==1.0.0` for the hybrid signing profile
- **Tests:** 30 with the extra installed, 18 without
- **Data:** synthetic, seed `20261120`, no real person, no network calls, no accounts

## 1. Process shape

```
seed 20261120 ──► cohort.py ──► 5,000 pseudonymous people
                                     │
                                     ▼
                           engine.run_cycle()
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
              ledger.jsonl                    person_view()
        append-only hash chain              rebuilt by replay
                     │                               │
                     └──────────► server.py ◄────────┘
                                  /api/* + index.html
```

Three properties matter to a reviewer:

1. **The ledger is the state.** There is no second store to drift from it. `engine._replay()`
   walks the chain at start and recomputes every person's status. Kill the process mid-pathway
   and it returns with exactly the view a verifier would compute.
2. **The engine is the policy boundary.** `Engine.approve()` refuses a person without outreach
   consent. A UI bug cannot become a governance failure because the refusal is below the
   interface.
3. **No hidden state.** The demo runs in one process, from a fixed seed, with no outbound
   network calls. Two runs on two machines produce byte-identical ledgers.

## 2. Module map

| File | Responsibility | Lines |
|---|---|---|
| `sel/canonical.py` | deterministic JSON and sha256 | 16 |
| `sel/ledger.py` | append, verify, head, checkpoints | 205 |
| `sel/cohort.py` | seeded synthetic cohort, pseudonyms | 55 |
| `sel/risk.py` | transparent points model | 64 |
| `sel/engine.py` | state machine, replay, queue, equity | 285 |
| `sel/verify.py` | CLI verifier, both layers | 101 |
| `sel/pqc.py` | hybrid signing and verification | 323 |
| `sel/hybrid.py` | hybrid runner and signing benchmark | 120 |
| `sel/forge.py` | signature-stripping forgery | 59 |
| `sel/tamper.py` | tamper harness, operates on a copy | 63 |
| `server.py` | stdlib HTTP API and static host | 248 |
| `web/index.html` | demo interface | 237 |

## 3. Record model

A record is canonical JSON. Sorted keys, no whitespace, UTF-8, so the same content hashes the
same way on any machine and in any language without a schema registry.

```json
{
  "seq": 3826,
  "sealed_at": "2026-11-02T00:12:44.118Z",
  "prev_hash": "a7b2f979e9f8dd97f513c5123eb94a25b5e0b02f...",
  "decision": "PENDING_APPROVAL",
  "subject": "psn_5b7def8245d19838eb6c1249",
  "person_id": "SEL-03827",
  "tier": "HIGH",
  "score": 11,
  "reasons": [
    {"factor": "variant_flag", "label": "Reported pathogenic variant flag",
     "category": "genomic", "points": 4, "observed": true}
  ],
  "inputs": {"age": 61, "sex": "F", "family_history": true, "...": "..."},
  "inputs_digest": "20fe67dd59fc9c5d7bfebf7eb4851ec8...",
  "model_id": "SEL-RISK",
  "model_version": "1.0.0",
  "thresholds": {"high": 6, "moderate": 4},
  "consent": {"secondary_use": true, "outreach": true, "preferred_channel": "phone"},
  "actor": {"type": "clinician", "id": "dr_kovacs", "role": "screening-lead"},
  "sig": "MEUCIQ...",
  "hash": "2fd1..."
}
```

Rules enforced in `ledger.py`:

- `hash = sha256(canonical_json(record without "hash"))`
- `prev_hash` holds the previous record's `hash`, so each hash commits to the entire history
  behind it. There is no way to edit record *n* without breaking *n+1* onwards.
- The hash covers `sig` when signing is on, so stripping a signature also breaks the chain.
- Sequence numbers are dense and monotonic. A gap or a reorder fails verification.

## 4. Pathway state machine

```
ASSESSED ──score below 4──────────────► NO_ACTION
   │
   ├──no secondary-use consent─────────► CONSENT_BLOCKED
   ├──no outreach consent──────────────► CONSENT_BLOCKED
   └──consented, score 4 or more───────► PENDING_APPROVAL
                                              │ clinician decision
                                              ▼
                                          APPROVED
                                              │ release to channel
                                              ▼
                                      OUTREACH_RELEASED
                                              │ response recorded
                                              ▼
                                           OUTCOME

HIGH tier: score 6 or more. MODERATE: 4 to 5. LOW: below 4.
```

Terminal states are `NO_ACTION`, `CONSENT_BLOCKED` and `OUTCOME`. Any transition not on this
graph raises, and the refusal path is itself a sealed record, so the absence of an action is
provable after the fact.

## 5. Scoring model

Eight rules, published in `sel/risk.py`, each returning its own points and label. The score is
the sum. No weights are hidden in code paths the record cannot see.

| Factor | Condition | Points | Category |
|---|---|---|---|
| `variant_flag` | reported pathogenic variant flag | 4 | genomic |
| `family_history` | family history of the screened condition | 3 | clinical |
| `age` | 60 or over | 2 | clinical |
| `age` | 50 to 59 | 1 | clinical |
| `years_since_screen` | 5 or more | 2 | pathway |
| `years_since_screen` | 3 to 4 | 1 | pathway |
| `smoker` | current smoker | 1 | clinical |
| `area_decile` | decile 3 or lower | 1 | equity, access not biology |

The equity factor is deliberately named as an access rule and carries one point, so a reviewer
who disagrees with that policy choice can see it and argue with it. Thresholds are 6 for HIGH
and 4 for MODERATE, both written into the record.

## 6. Verification

`verify()` is a single pass over the file:

1. Recompute each record's hash from its own content.
2. Compare `prev_hash` to the previous record's `hash`.
3. Check `seq` is dense and ordered.

It returns the **first failing index and a reason** (content mismatch, broken link, out of
order), not a boolean. An auditor needs localisation, not a verdict.

A line that is not valid JSON, not valid UTF-8, or a JSON value that is not a record object is
a **format error**, reported with its line number, rather than a shorter chain that still
verifies. A path that does not exist is an error too, not an empty ledger that reports success.

A dropped tail is a different case. Removing the last records leaves a chain that is internally
consistent, so on its own it verifies clean. `--expect-head` takes the head hash pinned out of
band and fails when the file stops short of it. Verify without a pinned head catches edits,
insertions and deletions in the middle; it catches a dropped tail only against the pinned head.

`verify_signatures()` then checks both halves and reports which one failed:

- Ed25519 signature on every record.
- ML-DSA-65 signature on the checkpoint covering that record.

The CLI exits non-zero on failure and prints the head hash, so the head can be anchored
externally (RFC 3161 timestamp, second custodian, public chain) without changing the format.
`--fingerprint` pins the signing key out of band, the same discipline as certificate pinning.

## 7. Hybrid signing

Two levels, because per-record ML-DSA is honest but slow.

| Level | Algorithm | Covers | Signature | Sign cost | Verify cost |
|---|---|---|---|---|---|
| Every record | Ed25519 (RFC 8032) | record body | 64 B | 0.03 ms | 0.11 ms |
| Every 250 records | ML-DSA-65 (FIPS 204) | Merkle root over the segment | 3,309 B | 10.17 ms | 0.18 ms |

5,841 signed records are covered by 25 checkpoints: one at the start and one every 250 records
after it. That is 25 ML-DSA-65 signatures, not 5,841. The timing above is Ed25519 per record
plus 25 post-quantum signings amortised across the cycle, which is 0.2 s of post-quantum
signing instead of 51 s, with every record inheriting the guarantee through the Merkle root.
The suite is declared per record (`hybrid-ed25519-mldsa65-v1`), so a future algorithm can be
added without re-cutting the chain.

`sel/forge.py` implements the attack the signature layer exists to stop: strip every signature,
recompute every hash. The result re-hashes from genesis and the chain reports `OK`, then
`verify_signatures()` fails at `seq 0` because the attacker holds no key.

The reverse attack is covered as well: `test_tampered_mldsa_checkpoint_is_caught` corrupts only
the ML-DSA half of a checkpoint, leaves Ed25519 intact, and verification reports
`ml-dsa half failed`. Both halves are load-bearing, not one plus a decoration.

The KEY record inside the ledger is self-signed. On its own it proves only that the file is
internally consistent. Trust beyond that requires pinning the fingerprint out of band, and the
verifier prints the key on every run for exactly that purpose.

## 8. API surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/summary` | counts, chain status, head hash |
| GET | `/api/queue` | approval queue, ordered by score |
| GET | `/api/equity` | selection and reach rates by age, sex, decile |
| GET | `/api/verify` | chain and signature status |
| GET | `/api/export?person=` | per-person audit pack |
| GET | `/api/export/cohort` | cohort-wide CSV |
| POST | `/api/approve` | clinician approval, identity and note sealed |
| POST | `/api/release` | outreach release |
| POST | `/api/outcome` | outcome recorded |
| POST | `/api/tamper` | tamper harness on a copy |
| POST | `/api/reset` | regenerate the demo ledger |

No authentication in the demo. Production substitutes the hospital identity provider at the
approval step, which is why the actor is a field in the record rather than a session detail.

## 9. Tests and CI

30 tests, 18 core and 12 hybrid. The core tests are `unittest` (no third-party dependency),
the hybrid tests are `pytest`. CI runs two jobs on Python 3.12: a stdlib job that seals, verifies
and tampers, and a hybrid job that installs the pinned extra and repeats seal, verify, tamper,
forge and the signing benchmark.

| Area | What is asserted |
|---|---|
| Canonical form | key order and whitespace cannot change the digest |
| Ledger | append, head, dense sequence, link integrity |
| Tamper | an edited field fails at that record, with the right index |
| Truncation | a dropped tail verifies alone and fails against the pinned head |
| Corrupt file | a truncated, non-UTF-8 or non-record line is a format error with its line number |
| Missing file | a path that does not exist exits 1 instead of reporting an empty ledger |
| Startup | a damaged ledger is refused before any further approval can be sealed |
| Consent | approval is refused without outreach consent, at engine level |
| Replay | state rebuilt from the ledger matches live state |
| Risk | reasons sum to the score, thresholds applied as published |
| Hybrid | every record signed, both halves verified, per-half failure reporting |
| Forgery | a rehashed chain with no signatures is refused at seq 0 |
| Keys | fingerprint stable, tampered signatures and checkpoints caught, gap reported |

## 10. Measured on this build

| Claim | Observed |
|---|---|
| Records sealed | 5,841 signed, 5,867 ledger lines with checkpoints |
| Unsigned cycle | 0.354 s for 5,000 assessments |
| Hybrid cycle | 0.716 s, 0.06 ms per record overhead |
| Chain verification | passes across 5,867 records |
| Hybrid verification | both halves verify across 5,841 records in 25 checkpoints |
| Tamper test | edit record 2, `BROKEN at seq 2`, live ledger intact |
| Forgery | chain `OK`, signatures `FAILED at seq 0` |
| Tests | 30 passed |

Regenerate every line with the commands below. Nothing in this table is an estimate.

## 11. Threat model and limits

- The bare chain is tamper-**evident**, not tamper-proof. Write access plus time is enough to
  rebuild it, which is the reason the signing profile exists. Precisely: tamper-evident to an
  observer holding the pinned head or the pinned key, not tamper-proof against an operator who
  controls both the store and the key.
- Signing moves the trust question to **key custody**. Self-signed keys prove internal
  consistency, not identity. Pin the fingerprint out of band.
- **Single writer** assumed. Concurrent writers need a sequencer or a log service.
- **A dropped tail is invisible without a pinned head.** Deleting the newest records leaves a
  shorter chain that is internally consistent. Pass `--expect-head` with the head recorded out
  of band, or anchor the head, and the truncation is caught.
- **No revocation path** yet. A compromised key cannot be retired in place. A pilot needs a
  named custodian, an offline or HSM-held key, a rotation schedule and a revocation procedure
  agreed before it holds real data. That is a deployment decision, not a code claim.
- The model is **illustrative and uncalibrated**, with no clinical validation and no outcome
  claim. The cohort is synthetic.
- **Shadow mode exercises the approval path on test cases only.** No outreach is released
  during the shadow run, so the first live approval happens after the review, with the same
  sealed record shape a test approval produces.
- Anchoring the head is still required in production. Signing and anchoring solve different
  halves of the same question.

## 12. Reproduce

```bash
git clone https://github.com/narko4u/triage-tek && cd triage-tek
python3 -m unittest discover -s tests -p "test_core.py" -v   # 18 core tests
python3 server.py --port 8795                    # first run generates data/ and runs a cycle
python3 -m sel.verify --ledger data/ledger.jsonl --chain-only
python3 -m sel.verify --ledger data/ledger.jsonl --chain-only --expect-head <hash from a trusted transcript>
python3 -m sel.tamper --ledger data/ledger.jsonl --out data/tampered.jsonl --field tier
python3 -m sel.verify --ledger data/tampered.jsonl --chain-only   # exits 1, names the record

pip install -r requirements-pqc.txt
python3 -m pytest tests -q                       # 30 passed
python3 -m sel.hybrid --data-dir data-hybrid --fresh
python3 -m sel.verify --ledger data-hybrid/ledger.jsonl

python3 -m sel.forge --ledger data-hybrid/ledger.jsonl \
  --out data-hybrid/forged.jsonl --field tier --value LOW
python3 -m sel.verify --ledger data-hybrid/forged.jsonl        # exits 1

python3 -m sel.hybrid --bench                     # primitive timings
SEL_DATA=data-hybrid SEL_HYBRID=1 python3 server.py --port 8795
```

Built by Security Division, Empire Labs Pty Ltd. MIT licence.
