# Rubric map

The organiser's six criteria, and the specific evidence for each.

## 1. Health impact and clinical relevance

The pathway targets the point where screening programmes lose people: between a positive
flag and a completed screen. Evidence in the build: the queue is ordered by risk, every
outreach carries a consent check and a human approver, and the outcome (booked, declined, no
response) is sealed so the programme can measure its own funnel rather than guessing.

Honest position: this is infrastructure for screening, not a new clinical intervention. Its
impact is on completion rates and on the ability to run a programme that survives audit.

## 2. Technical depth and architecture

- Append-only hash chain where each record commits to its predecessor (`sel/ledger.py`).
- State rebuilt by replay from the ledger, so restart cannot disagree with the record
  (`Engine._replay`).
- Canonical JSON so hashes are portable across languages and machines (`sel/canonical.py`).
- Consent enforced inside the state machine, not in the UI (`Engine.approve` refuses).
- **Hybrid post-quantum signing**: Ed25519 on every record, ML-DSA-65 (FIPS 204) over a Merkle
  root every 250 records, both halves required, algorithm named in the record so a future
  suite can be added without re-cutting the chain (`sel/pqc.py`, `docs/HYBRID-PQC.md`).
- **The forgery is shipped, not described**: `sel/forge.py` rebuilds the ledger with every
  signature stripped and every hash recomputed, and the verifier refuses it.
- Zero runtime dependencies in the default profile; stdlib HTTP server; the whole system runs
  offline. The signing extra is opt-in.
- 37 tests: 24 core covering chain integrity, tamper localisation, deletion and truncation detection, consent
  refusal, transition ordering and replay, plus 12 for the hybrid profile including a
  signature-stripping forgery.

## 3. Working solution and demonstration quality

Working, not mocked: 5,000 synthetic people assessed in 0.354 s, 5,841 sealed records, chain
verification clean, tamper test failing at the exact edited record. With the hybrid profile:
5,867 records, 25 ML-DSA-65 checkpoints, both halves verifying, and a forged copy refused.
The demo is one command.
`docs/DEMO.md` is the four-minute script.

## 4. Responsible AI, safety and data governance

- **Consent before action**, two separate permissions, checked in the engine.
- **Human in the loop** before any contact, with approver identity and role sealed.
- **Explainability at decision time**: the reason chain with points and observed values is
  sealed with the decision, not regenerated afterwards by a post-hoc tool.
- **Equity reporting** by age band, sex and area decile, with the access factor visible as a
  named rule rather than buried in a weight.
- **Data minimisation**: pseudonymous subjects, digests of inputs, no raw record content in
  the ledger.
- **Evidence designed to outlive its algorithm**: every record is bound into a post-quantum
  signed checkpoint, so a record sealed today is designed to keep verifying after the classical
  algorithms are retired. Stated as design intent, not as a guaranteed outcome. Key custody is named as the remaining trust dependency rather than hidden.
- **Limits published**: `docs/LIMITATIONS.md` states the tamper-evident boundary of the bare
  chain, the key custody dependency, the synthetic data, the missing revocation path and the
  uncalibrated model.

## 5. Scalability and deployment readiness

- Stateless HTTP handlers over an append-only file: horizontal read scaling is trivial.
- Verification is linear and can run on a sample or the whole chain.
- Deployment path documented in `docs/ARCHITECTURE.md`: WORM object storage, external
  timestamping of the head, existing identity provider for approvers. The record format does
  not change.
- Known ceiling stated: single-writer file storage. Production uses an append-only store with
  a sequencer.

## 6. Commercial viability and path to pilot

Buyer: a national or state screening programme, a health insurer running preventive
programmes, or a hospital group with population-health obligations. The same artefact is the
evidence sidecar for any organisation deploying AI in a regulated pathway, which is the
larger market.

Pilot path: one screening pathway, one site, six weeks, scoped to producing an audit pack for
a sample of 200 decisions and passing an independent review of the chain. Success is the
auditor accepting the record without asking for a spreadsheet.

Pricing model and pilot scope are in the submission deck, not in this repository.
