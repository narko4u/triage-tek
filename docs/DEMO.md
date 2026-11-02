# Demo script - four minutes

Run: `python3 server.py --port 8795`, open `http://127.0.0.1:8795`.

## 0:00 - the claim (20 s)

"Every screening programme can tell you who it flagged. Almost none can prove, six months
later, what data was used, which model version scored it, whether the person consented, and
who approved the contact. This is that record."

## 0:20 - the queue (40 s)

Point at the header: **chain OK, 5,844 records**. Left panel is the approval queue, ordered by
risk. Click the top row.

Read the detail panel out loud: tier and score, consent badges, then the reason table. "Four
points for a reported pathogenic variant, three for family history, two for age, one for the
screening gap. The score is not a black box, and this decomposition is sealed at the moment of
the decision, not reconstructed later."

## 1:00 - the human gate (40 s)

Press **Approve outreach**. Point at the flash: `sealed at seq 5841 · 2fd1…`. Then **Release
outreach**, then **Record outcome: booked**. The chain table for this person now shows five
records, each with an actor.

"Note what the engine refused to do: a person without outreach consent cannot reach this
button at all. The refusal is in the state machine, not the interface."

## 1:40 - the tamper test (60 s)

Scroll to the Verifier tab. Press **Verify chain** first: chain intact.

Now press **Tamper with one record, then verify**. The panel shows the edit (record 2, HIGH to
LOW) and the result: `BROKEN at seq 2`. Underneath, the live ledger still verifies clean,
because the test ran on a copy.

"That is the difference between a policy and a control. The policy says do not alter records.
The control makes alteration visible, at the record that was altered."

## 2:40 - equity (30 s)

Equity tab. Flag rate and reached rate by age band, sex and area decile. Point at the decile
table: "the access factor is a named rule worth one point, not a hidden weight. If the panel
disagrees with that policy choice, it is visible and arguable."

## 3:10 - the limits (30 s)

"Do not take my word for the boundary: the limitations page says the chain is tamper-evident,
not tamper-proof, that the cohort is synthetic, that the model is uncalibrated, and that
revocation is not implemented. A compliance product that hides its own limits is not a
compliance product."

## 3:40 - close (20 s)

"One pathway, one site, six weeks to produce an audit pack for 200 decisions and have an
independent reviewer accept the chain. That is the pilot."
