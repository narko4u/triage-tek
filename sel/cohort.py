"""Synthetic population cohort.

Everything here is generated. No real person, no real patient record and no real
genomic data is used anywhere in this project. The generator is seeded so the
same cohort can be reproduced byte for byte, which is what makes the demo
auditable.

Fields are deliberately the kind a national screening programme actually holds:
age, sex, family history, screening history, a genomic-style variant flag,
smoking status, an area-level socioeconomic decile, and consent state for
secondary use and for outreach.
"""
import random

COHORT_SIZE = 5000
SEED = 20261120


def _decile(rng):
    # skew towards the middle, with real representation at both tails
    return max(1, min(10, int(round(rng.gauss(5.5, 2.2)))))


def generate(size=COHORT_SIZE, seed=SEED):
    rng = random.Random(seed)
    people = []
    for i in range(size):
        sex = rng.choice(["F", "M"])
        age = int(max(18, min(84, rng.gauss(52, 15))))
        family_history = rng.random() < (0.14 if sex == "F" else 0.09)
        variant_flag = rng.random() < 0.031
        last_screen = rng.choice([0, 0, 1, 1, 2, 3, 4, 5, 6, 8, 10])
        smoker = rng.random() < 0.13
        decile = _decile(rng)
        person = {
            "person_id": "SEL-%05d" % (i + 1),
            "age": age,
            "sex": sex,
            "family_history": family_history,
            "variant_flag": variant_flag,
            "years_since_screen": last_screen,
            "smoker": smoker,
            "area_decile": decile,
            "consent_secondary_use": rng.random() < 0.82,
            "consent_outreach": rng.random() < 0.76,
            "preferred_channel": rng.choice(["sms", "phone", "letter", "app"]),
        }
        people.append(person)
    return people


def pseudonym(person_id):
    """Stable pseudonym so the ledger never carries the raw cohort identifier."""
    import hashlib
    return "psn_" + hashlib.sha256(("sel:" + person_id).encode()).hexdigest()[:24]
