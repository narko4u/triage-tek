import json
import os
import tempfile
import unittest

from sel import cohort, risk
from sel.engine import Engine
from sel.ledger import Ledger
from sel.tamper import tamper


class TestCanonical(unittest.TestCase):
    def test_digest_is_stable_and_order_independent(self):
        from sel.canonical import digest
        a = digest({"b": 1, "a": [1, 2]})
        b = digest({"a": [1, 2], "b": 1})
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)


class TestCohort(unittest.TestCase):
    def test_seeded_cohort_is_reproducible(self):
        a = cohort.generate(50, 7)
        b = cohort.generate(50, 7)
        self.assertEqual(a, b)

    def test_pseudonym_is_stable_and_not_the_id(self):
        p = cohort.pseudonym("SEL-00001")
        self.assertEqual(p, cohort.pseudonym("SEL-00001"))
        self.assertNotIn("SEL-00001", p)
        self.assertTrue(p.startswith("psn_"))


class TestRisk(unittest.TestCase):
    def test_reason_points_sum_to_score(self):
        people = cohort.generate(300, 11)
        for person in people:
            a = risk.assess(person)
            self.assertEqual(sum(r["points"] for r in a["reasons"]), a["score"])
            self.assertIn(a["tier"], ("HIGH", "MODERATE", "LOW"))

    def test_thresholds_are_applied(self):
        person = {"age": 30, "sex": "M", "family_history": False, "variant_flag": False,
                  "years_since_screen": 0, "smoker": False, "area_decile": 8}
        self.assertEqual(risk.assess(person)["tier"], "LOW")
        person["variant_flag"] = True
        person["family_history"] = True
        self.assertEqual(risk.assess(person)["tier"], "HIGH")


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "l.jsonl")

    def test_append_and_verify(self):
        led = Ledger(self.path)
        for i in range(5):
            led.append(decision="ASSESSED", subject="psn_%d" % i, actor={"type": "system", "id": "t"})
        ok, bad, detail = led.verify()
        self.assertTrue(ok, detail)
        self.assertEqual(len(led), 5)

    def test_edit_is_detected_at_the_edited_record(self):
        led = Ledger(self.path)
        for i in range(5):
            led.append(decision="ASSESSED", subject="psn_%d" % i, tier="LOW")
        copy = os.path.join(self.dir, "t.jsonl")
        tamper(self.path, copy, 2, "tier", "HIGH")
        ok, bad, _ = Ledger(copy).verify()
        self.assertFalse(ok)
        self.assertEqual(bad, 2)

    def test_deletion_breaks_the_chain(self):
        led = Ledger(self.path)
        for i in range(4):
            led.append(decision="ASSESSED", subject="psn_%d" % i)
        with open(self.path) as fh:
            rows = [json.loads(l) for l in fh]
        rows.pop(1)
        with open(self.path, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
        ok, bad, _ = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertEqual(bad, 1)


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.engine = Engine(self.dir)

    def test_cycle_seals_one_record_per_person_and_queue_is_consented_only(self):
        result = self.engine.run_cycle()
        self.assertTrue(result["chain_ok"], result)
        self.assertEqual(result["assessed"], len(self.engine.cohort))
        for row in self.engine.queue(limit=999):
            person = self.engine.by_id[row["person_id"]]
            self.assertTrue(person["consent_secondary_use"], row)
            self.assertTrue(person["consent_outreach"], row)

    def test_unconsented_person_cannot_be_approved(self):
        self.engine.run_cycle()
        blocked = [p for p in self.engine.cohort if not p["consent_outreach"]][0]
        with self.assertRaises(ValueError):
            self.engine.approve(blocked["person_id"], "dr.test", "clinician")

    def test_full_pathway_is_sealed_in_order(self):
        self.engine.run_cycle()
        pid = self.engine.queue(1)[0]["person_id"]
        self.engine.approve(pid, "dr.test", "clinician", "ok")
        self.engine.release(pid, "dr.test")
        self.engine.record_outcome(pid, "booked")
        view = self.engine.person_view(pid)
        decisions = [r["decision"] for r in view["chain"]]
        self.assertEqual(decisions, ["ASSESSED", "PENDING_APPROVAL", "APPROVED", "OUTREACH_RELEASED", "OUTCOME"])
        self.assertTrue(self.engine.ledger.verify()[0])

    def test_release_before_approval_is_refused(self):
        self.engine.run_cycle()
        pid = self.engine.queue(1)[0]["person_id"]
        with self.assertRaises(ValueError):
            self.engine.release(pid, "dr.test")

    def test_replay_after_restart_matches(self):
        self.engine.run_cycle()
        pid = self.engine.queue(1)[0]["person_id"]
        self.engine.approve(pid, "dr.test", "clinician")
        fresh = Engine(self.dir)
        self.assertEqual(fresh.person_view(pid)["status"], "APPROVED")
        self.assertEqual(len(fresh.ledger), len(self.engine.ledger))


if __name__ == "__main__":
    unittest.main()
