# Architecture

## The problem, stated precisely

Population screening does not usually fail because the model is wrong. It fails at the
handover. A person is flagged, an outreach attempt is or is not made, and later nobody can
reconstruct what happened. The four questions that always get asked are:

1. What data was used for this decision?
2. Which model, which version, which threshold?
3. Did consent cover this use?
4. Who approved contact with this person?

If those four answers are not in a record that existed *before* the question was asked, the
organisation has to reconstruct them from application logs, email and memory. That is the gap
this prototype fills.

## Design position

**Seal the decision, not just the data.** A hash of the input dataset proves the data was not
changed. It does not prove which inputs fed *this* decision, which model version scored it, or
who authorised the next step. The unit of evidence is the transition.

**The ledger is the state.** On startup the engine replays the chain and rebuilds the status of
every person. There is no separate database to drift out of agreement with the record. If the
process restarts mid-pathway, it comes back with the same view a verifier would compute.

**Consent is enforced in the engine.** The API surface cannot approve a consent-blocked person,
because `Engine.approve` refuses the transition. A UI bug cannot become a governance failure.

**One record, one decision, one hash.** Records are canonical JSON (sorted keys, no whitespace,
UTF-8) so the same content always hashes the same way on any machine, in any language, without
a schema registry.

## Record format

```json
{
  "seq": 3826,
  "ts": "2026-11-02T00:12:44.118Z",
  "decision": "PENDING_APPROVAL",
  "subject": "psn_5b7def8245d19838eb6c1249",
  "person_id": "SEL-03827",
  "tier": "HIGH",
  "score": 11,
  "reasons": [{"factor": "variant_flag", "points": 4, "label": "...", "observed": true}],
  "inputs_digest": "9f2c...",
  "model_id": "SEL-RISK",
  "model_version": "1.0.0",
  "thresholds": {"high": 6, "moderate": 4},
  "consent": {"secondary_use": true, "outreach": true},
  "actor": {"type": "system", "id": "sel-engine"},
  "prev": "4318...",
  "sig": "MEUCIQ...",
  "hash": "2fd1..."
}
```

`hash = sha256(canonical_json(record without "hash"))`, and the record includes `prev`, so the
hash commits to the entire history behind it. When the hybrid profile is on, `sig` holds an
Ed25519 signature over the record body, and the hash covers the signature as well, so removing
a signature also breaks the chain.

## Signing

Two algorithms, two levels, both required at verification time.

| Level | Algorithm | Covers | Cost |
|---|---|---|---|
| every record | Ed25519 | the record body | 0.03 ms, 64 B |
| every 250 records | ML-DSA-65 (FIPS 204) | a Merkle root over that segment | 10 ms, 3,309 B |

The record is authoritative for the classical half; the checkpoint is authoritative for the
post-quantum half, and every record inherits it through the Merkle root. The type is declared
in the record (`suite: hybrid-ed25519-mldsa65-v1`) so a future algorithm can be added without
re-cutting the chain. `sel/forge.py` builds the attack this layer exists to stop: it strips
every signature and recomputes every hash, which a bare chain cannot detect.

The profile is optional. Without the extra installed the ledger is unsigned and the chain
still works, which keeps the default quick start dependency free.

## Pathway

```
ASSESSED ──low score──────────────► NO_ACTION
   │
   ├──no secondary-use consent─────► CONSENT_BLOCKED
   ├──no outreach consent──────────► CONSENT_BLOCKED
   └──consented, above threshold───► PENDING_APPROVAL
                                          │ clinician decision
                                          ▼
                                      APPROVED
                                          │ release to channel
                                          ▼
                                  OUTREACH_RELEASED
                                          │ response recorded
                                          ▼
                                       OUTCOME
```

Terminal states are NO_ACTION, CONSENT_BLOCKED and OUTCOME. The engine refuses any transition
that does not follow this graph.

## Components

| File | Responsibility | Lines |
|---|---|---|
| `sel/canonical.py` | deterministic JSON and sha256 | 16 |
| `sel/ledger.py` | append, verify, head, checkpoints | 157 |
| `sel/cohort.py` | seeded synthetic cohort, pseudonyms | 55 |
| `sel/risk.py` | transparent points model | 64 |
| `sel/engine.py` | state machine, replay, equity, queue | 276 |
| `sel/verify.py` | CLI verifier, both layers | 62 |
| `sel/pqc.py` | hybrid signing and verification | 323 |
| `sel/hybrid.py` | hybrid runner and benchmark | 120 |
| `sel/forge.py` | signature-stripping forgery | 59 |
| `sel/tamper.py` | tamper harness on a copy | 63 |
| `server.py` | stdlib HTTP API and static host | 207 |
| `web/index.html` | demo interface | 237 |
| `tests/test_core.py` | 13 core unit tests | 136 |
| `tests/test_hybrid.py` | 12 hybrid profile tests | 172 |

## Verification

`verify()` recomputes every record's hash from its own content and checks that `prev` equals
the previous record's `hash`. It returns the first index that fails and a reason: content
mismatch, broken link, or out-of-order sequence. `verify_signatures()` then checks both halves,
the Ed25519 signature on every record and the ML-DSA-65 checkpoint that covers it, and reports
which half failed, not just that something did. A verifier that only says "invalid" is not
useful to an auditor; localisation is the point.

The head hash is exposed at `/api/verify` and printed by the CLI so it can be anchored
externally (RFC 3161 timestamp, second custodian, public chain) without changing the format.

## Deployment path

The prototype is standard-library Python and a single HTML file. The production shape is the
same code with three substitutions: object storage with WORM retention instead of a local
file, an external timestamp on each sealed head, and the existing hospital identity provider
for approver authentication. None of those change the record format or the verification
logic, which is why the prototype is worth building rather than describing.
