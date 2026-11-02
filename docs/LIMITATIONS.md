# Limitations

Stated up front, because a compliance claim that hides its own limits is not a compliance
claim.

## What this is not

- **Not a medical device.** No regulatory clearance, no clinical validation, no diagnostic use.
- **Not calibrated.** The points system in `sel/risk.py` is illustrative. It was not fitted to
  any population and its thresholds are not clinically derived. A real deployment would need
  a validated model, a calibration study and a monitoring plan for drift.
- **Not outcome evidence.** Nothing here demonstrates that the pathway improves health
  outcomes. Demonstrating that needs a trial, not a prototype.

## Data

- **Synthetic only.** The cohort is generated from a fixed seed. There is no real patient data
  in this repository, and the demo cannot leak any because none is present.
- **The synthetic cohort carries realistic inequities on purpose.** Screening history, smoking
  and area decile are correlated with age and sex the way real populations are, so the equity
  view has something to reveal. The correlations are plausible, not measured.

## Integrity

- **Tamper-evident, not tamper-proof.** Each record hashes its own content plus the previous
  record's hash. That detects edits, insertions and deletions, and localises them. It does not
  prevent someone with write access from recomputing the chain from the edit point forward.
  The mitigation is publication: send the head hash somewhere the writer does not control
  (a timestamping authority, a second custodian, or a public chain). The prototype exposes the
  head hash so that anchoring can be added without changing the record format.
- **The tamper demo edits a copy.** The live ledger is never modified by the demo, which is why
  it verifies clean immediately afterwards. A demo that damaged its own evidence would prove
  the opposite of the claim.
- **Local file storage.** SQLite or an append-only object store with WORM retention is the
  production answer. A local JSONL file is the prototype answer.

## Consent and governance

- **Consent is modelled as two booleans.** Real consent is granular, revocable, and has an
  expiry and a purpose. The model here is the minimum that makes the point: secondary use and
  outreach are separate permissions and both are checked before action.
- **Withdrawal is not implemented.** A real system must support revocation, and must record
  that it was honoured. This prototype has no revocation path.
- **No identity resolution.** Records are keyed by pseudonym. Linking to a real person happens
  in the outreach system, which is outside this prototype.

## Equity

- **Area decile is used as an access factor, not biology.** It adds one point because
  access barriers cause late presentation. That is a policy choice, visible in the reason
  chain, and open to challenge. It is not hidden inside a model weight.
- **The equity report is descriptive.** It shows flag and release rates by age band, sex and
  decile. It does not compute confidence intervals and does not test for disparity.

## Operations

- **Single process, single node.** Thread-safe within the process, with a lock around writes.
  Multi-writer coordination is not attempted.
- **No authentication on the demo server.** It binds to localhost only. There is no login
  because there are no real users; adding one would be security theatre rather than security.
- **Restart rebuilds state from the ledger.** If the ledger is lost, the state is lost. There is
  no separate database to recover from, by design, so the record cannot disagree with itself.
