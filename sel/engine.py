"""The screening pathway state machine.

Every transition is sealed. The engine never holds state that the ledger does not
hold: on startup the state of each person is rebuilt by replaying the chain, so a
restart cannot disagree with the record.
"""
import json
import os
import threading

from . import cohort as cohort_mod
from . import risk as risk_mod
from .canonical import digest
from .ledger import Ledger, utc_now

DECISIONS = (
    "ASSESSED",
    "NO_ACTION",
    "CONSENT_BLOCKED",
    "PENDING_APPROVAL",
    "APPROVED",
    "OUTREACH_RELEASED",
    "OUTCOME",
)

TERMINAL = {"NO_ACTION", "CONSENT_BLOCKED", "OUTCOME"}


class LedgerIntegrityError(RuntimeError):
    """The ledger on disk does not verify, so the engine must not act on it."""


class UnknownPerson(KeyError):
    """The person id is not in the cohort. Distinct from a bad request."""


class Engine:
    def __init__(self, data_dir, signer=None):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.ledger = Ledger(os.path.join(data_dir, "ledger.jsonl"), signer=signer)
        if signer is not None and not self.ledger.all():
            self.ledger.add_key_record()
            self.ledger.seal_checkpoint()
        ok, bad, detail = self.ledger.verify()
        if not ok:
            raise LedgerIntegrityError(
                "refusing to act on a ledger that does not verify: %s at seq %s" % (detail, bad)
            )
        if any(r.get("kind") == "KEY" for r in self.ledger.all()):
            sig = self.ledger.verify_signatures()
            if not sig["ok"]:
                raise LedgerIntegrityError(
                    "refusing to act on a ledger whose signatures do not verify: %s"
                    % sig["detail"]
                )
        self._lock = threading.RLock()
        self.cohort = self._load_cohort()
        self.by_id = {p["person_id"]: p for p in self.cohort}
        self.state = {}
        self._replay()

    # ---- cohort --------------------------------------------------------
    def _load_cohort(self):
        path = os.path.join(self.data_dir, "cohort.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        people = cohort_mod.generate()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(people, fh)
        return people

    # ---- replay --------------------------------------------------------
    def _replay(self):
        self.state = {}
        for rec in self.ledger.all():
            if rec.get("kind"):
                continue
            subj = rec["subject"]
            entry = self.state.setdefault(subj, {"records": [], "status": None, "person_id": rec.get("person_id")})
            entry["records"].append(rec["seq"])
            entry["status"] = rec["decision"]
            if rec.get("person_id"):
                entry["person_id"] = rec["person_id"]

    # ---- cycle ---------------------------------------------------------
    def run_cycle(self):
        """Assess the whole cohort and seal one record per person.

        Completion is derived from the ledger: every cohort member carries an
        assessment record. A cycle interrupted part way through is resumed, not
        mistaken for a finished one, and people already assessed are not
        assessed twice.
        """
        with self._lock:
            done = {
                entry.get("person_id")
                for entry in self.state.values()
                if entry.get("status")
            }
            if len(done) >= len(self.cohort):
                return {"skipped": True, "reason": "cycle already complete"}
            seq_of = {}
            for person in self.cohort:
                if person["person_id"] in done:
                    subj = cohort_mod.pseudonym(person["person_id"])
                    seq_of[person["person_id"]] = self.state[subj]["records"][0]
                    continue
                assessment = risk_mod.assess(person)
                subj = cohort_mod.pseudonym(person["person_id"])
                decision = "ASSESSED"
                if assessment["tier"] == "LOW":
                    decision = "NO_ACTION"
                elif not person["consent_secondary_use"]:
                    decision = "CONSENT_BLOCKED"
                elif not person["consent_outreach"]:
                    decision = "CONSENT_BLOCKED"

                rec = self.ledger.append(
                    _fsync=False,
                    decision=decision,
                    subject=subj,
                    person_id=person["person_id"],
                    tier=assessment["tier"],
                    score=assessment["score"],
                    reasons=assessment["reasons"],
                    inputs=assessment["inputs"],
                    inputs_digest=assessment["inputs_digest"],
                    model_id=assessment["model_id"],
                    model_version=assessment["model_version"],
                    thresholds={
                        "high": assessment["threshold_high"],
                        "moderate": assessment["threshold_moderate"],
                    },
                    consent={
                        "secondary_use": person["consent_secondary_use"],
                        "outreach": person["consent_outreach"],
                        "preferred_channel": person["preferred_channel"],
                    },
                    actor={"type": "system", "id": "sel-engine"},
                )
                seq_of[person["person_id"]] = rec["seq"]

            # anyone who cleared consent and is above threshold is queued for a human
            queued = 0
            for person in self.cohort:
                subj = cohort_mod.pseudonym(person["person_id"])
                if self.state.get(subj, {}).get("status") not in (None, "ASSESSED"):
                    continue
                assessment = risk_mod.assess(person)
                if assessment["tier"] == "LOW":
                    continue
                if not (person["consent_secondary_use"] and person["consent_outreach"]):
                    continue
                self.ledger.append(
                    _fsync=False,
                    decision="PENDING_APPROVAL",
                    subject=cohort_mod.pseudonym(person["person_id"]),
                    person_id=person["person_id"],
                    tier=assessment["tier"],
                    score=assessment["score"],
                    assessment_seq=seq_of[person["person_id"]],
                    requested_action="screening_outreach",
                    channel=person["preferred_channel"],
                    actor={"type": "system", "id": "sel-engine"},
                )
                queued += 1
            self.ledger.flush()
            self._replay()
            ok, bad, detail = self.ledger.verify()
            return {
                "skipped": False,
                "assessed": len(self.cohort),
                "queued_for_approval": queued,
                "records": len(self.ledger),
                "chain_ok": ok,
                "detail": detail,
            }

    # ---- transitions ---------------------------------------------------
    def _person(self, person_id):
        if not isinstance(person_id, str):
            raise UnknownPerson(person_id)
        person = self.by_id.get(person_id)
        if not person:
            raise UnknownPerson(person_id)
        return person

    def approve(self, person_id, approver_id, approver_role, note=""):
        with self._lock:
            person = self._person(person_id)
            subj = cohort_mod.pseudonym(person_id)
            if self.state.get(subj, {}).get("status") != "PENDING_APPROVAL":
                raise ValueError("not awaiting approval")
            rec = self.ledger.append(
                decision="APPROVED",
                subject=subj,
                person_id=person_id,
                approver={"id": approver_id, "role": approver_role},
                note=note,
                actor={"type": "human", "id": approver_id},
            )
            self._replay()
            self.ledger.seal_checkpoint()
            return rec

    def release(self, person_id, released_by):
        with self._lock:
            person = self._person(person_id)
            subj = cohort_mod.pseudonym(person_id)
            if self.state.get(subj, {}).get("status") != "APPROVED":
                raise ValueError("not approved")
            rec = self.ledger.append(
                decision="OUTREACH_RELEASED",
                subject=subj,
                person_id=person_id,
                channel=person["preferred_channel"],
                contact_ref="outreach-" + digest({"p": person_id, "n": len(self.ledger)}),
                released_by=released_by,
                actor={"type": "human", "id": released_by},
            )
            self._replay()
            self.ledger.seal_checkpoint()
            return rec

    def record_outcome(self, person_id, outcome, recorded_by="sel-engine"):
        with self._lock:
            if outcome not in ("booked", "declined", "no_response"):
                raise ValueError("unknown outcome")
            self._person(person_id)
            subj = cohort_mod.pseudonym(person_id)
            if self.state.get(subj, {}).get("status") != "OUTREACH_RELEASED":
                raise ValueError("outreach not released")
            rec = self.ledger.append(
                decision="OUTCOME",
                subject=subj,
                person_id=person_id,
                outcome=outcome,
                actor={"type": "system", "id": recorded_by},
            )
            self._replay()
            self.ledger.seal_checkpoint()
            return rec

    # ---- views ---------------------------------------------------------
    def person_view(self, person_id):
        person = self._person(person_id)
        subj = cohort_mod.pseudonym(person_id)
        assessment = risk_mod.assess(person)
        return {
            "person": person,
            "pseudonym": subj,
            "assessment": assessment,
            "status": self.state.get(subj, {}).get("status"),
            "chain": [self.ledger.all()[i] for i in self.state.get(subj, {}).get("records", [])],
        }

    def queue(self, limit=200, offset=0):
        out = []
        for subj, entry in self.state.items():
            if entry.get("status") in ("PENDING_APPROVAL", "APPROVED"):
                pid = entry.get("person_id")
                person = self.by_id.get(pid)
                if not person:
                    continue
                a = risk_mod.assess(person)
                out.append({
                    "person_id": pid,
                    "tier": a["tier"],
                    "score": a["score"],
                    "status": entry["status"],
                    "channel": person["preferred_channel"],
                    "age": person["age"],
                    "sex": person["sex"],
                })
        out.sort(key=lambda r: (-r["score"], r["person_id"]))
        return out[offset:offset + limit]

    def summary(self):
        counts = {}
        for entry in self.state.values():
            counts[entry.get("status")] = counts.get(entry.get("status"), 0) + 1
        ok, bad, detail = self.ledger.verify()
        return {
            "cohort_size": len(self.cohort),
            "records": len(self.ledger),
            "head": self.ledger.head,
            "chain_ok": ok,
            "first_bad_seq": bad,
            "detail": detail,
            "counts": counts,
            "model": {"id": risk_mod.MODEL_ID, "version": risk_mod.MODEL_VERSION},
            "sealed_at": utc_now(),
        }

    def equity(self):
        buckets = {}
        for person in self.cohort:
            subj = cohort_mod.pseudonym(person["person_id"])
            status = self.state.get(subj, {}).get("status")
            a = risk_mod.assess(person)
            band = "18-39" if person["age"] < 40 else "40-49" if person["age"] < 50 else "50-59" if person["age"] < 60 else "60-69" if person["age"] < 70 else "70+"
            for dim, key in (("age_band", band), ("sex", person["sex"]), ("area_decile", str(person["area_decile"]))):
                b = buckets.setdefault(dim, {}).setdefault(key, {"people": 0, "flagged": 0, "high": 0, "released": 0})
                b["people"] += 1
                if a["tier"] != "LOW":
                    b["flagged"] += 1
                if a["tier"] == "HIGH":
                    b["high"] += 1
                if status in ("OUTREACH_RELEASED", "OUTCOME"):
                    b["released"] += 1
        for dim, keys in buckets.items():
            for k, b in keys.items():
                b["flag_rate"] = round(b["flagged"] / b["people"], 4) if b["people"] else 0.0
                b["release_rate"] = round(b["released"] / b["people"], 4) if b["people"] else 0.0
        return buckets
