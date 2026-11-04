# TriageTek

![ci](https://github.com/narko4u/triage-tek/actions/workflows/ci.yml/badge.svg)

**Screening evidence infrastructure for population health programmes.**

TriageTek is a working prototype for the **Future Health Digital Innovation Challenge** (Challenge 04,
Precision Prevention and Screening), GITEX Dubai 2026.

It does not try to out-model anyone. It answers the question a screening
programme cannot answer today: **can you prove what happened to this person's data and this
person's decision, six months later, to an auditor who was not in the room?**

Every step is sealed into an append-only hash chain. Change one field in one record and
verification fails at that record.

*TriageTek for the Future Health Digital Innovation Challenge: consent first, human approval, every decision preserved.*

![TriageTek marketing image](docs/images/triagetek-marketing.png)

## Quick start

```bash
git clone https://github.com/narko4u/triage-tek && cd triage-tek
python3 server.py --port 8795
# open http://127.0.0.1:8795
```

No dependencies, no network calls, no accounts. Python 3.11+.

```bash
python3 -m unittest discover -s tests -v      # 13 tests
python3 -m sel.verify --ledger data/ledger.jsonl
python3 -m sel.tamper --ledger data/ledger.jsonl --out data/tampered.jsonl --field tier
python3 -m sel.verify --ledger data/tampered.jsonl   # exits 1, names the bad record
```

## What it does

1. **Generates a synthetic cohort** of 5,000 people from a fixed seed, so the run reproduces
   byte for byte. No real person, no real record, no genomic data from anyone real.
2. **Scores each person** with a published, transparent points system (`SEL-RISK 1.0.0`).
   The score is decomposed at decision time into named factors, points and observed values.
3. **Applies consent before action.** No secondary use without consent. No outreach without
   outreach consent. A consent-blocked person cannot be approved by any role, because the
   transition is refused by the engine, not by the interface.
4. **Requires human approval** before any contact is released. The approver's identity, role
   and note are sealed with the decision.
5. **Seals every transition**: ASSESSED, NO_ACTION, CONSENT_BLOCKED, PENDING_APPROVAL,
   APPROVED, OUTREACH_RELEASED, OUTCOME.
6. **Verifies on demand**, and exports a per-person audit pack or a cohort-wide CSV.

## What it looks like

*Approval queue on the left, the sealed decision record on the right. Every row is a synthetic person; every transition is sealed.*

![Approval queue and decision detail](docs/images/queue-and-decision.png)

*After the tamper test: the edited copy fails at record 2, the live ledger still verifies clean.*

![Verifier after the tamper test](docs/images/verifier-tamper.png)

## Measured on this build

| Claim | Observed |
|---|---|
| Records sealed | 5,844 across 5,000 people |
| Chain verification | `chain intact across 5,844 records` |
| Tamper test | edited record 2, `HIGH` to `LOW`; verifier `BROKEN at seq 2` |
| Live ledger after tamper test | still intact (the test runs on a copy) |
| Tests | 13 passed |
| Cycle runtime | 0.5 s for 5,000 assessments |

Numbers above are from an actual run on this machine, not estimates. Regenerate them with
the commands in Quick start.

## Honest limits

The cohort is synthetic. The risk model is illustrative and uncalibrated. There is no
clinical validation and no outcome claim. The chain is tamper-**evident**, not
tamper-proof: someone with write access can rewrite the chain from the edit forward, which
is exactly why the head hash gets published elsewhere. Full list in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Layout

```
sel/
  sel/canonical.py   canonical JSON + sha256
  sel/ledger.py      append-only hash-chained ledger
  sel/cohort.py      seeded synthetic cohort
  sel/risk.py        transparent points model
  sel/engine.py      pathway state machine, rebuilt from the ledger on restart
  sel/verify.py      CLI verifier
  sel/tamper.py      tamper harness (works on a copy)
  server.py          stdlib HTTP server, no dependencies
  web/index.html     demo interface
  tests/             13 unit tests
  data/              generated cohort and ledger
  docs/              architecture, limits, demo script, rubric map
```

## Licence and attribution

MIT. Built by Security Division, Empire Labs Pty Ltd.
