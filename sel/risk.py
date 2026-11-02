"""Transparent risk stratification.

The point of this module is not that the model is clever. The point is that
every score can be decomposed, at the moment of the decision, into the exact
inputs and weights that produced it. That decomposition is what gets sealed
into the ledger, so a challenge six months later can be answered from the
record rather than from a notebook nobody kept.

The scoring is a published points system. It is illustrative, not calibrated to
any real population, and it is not a medical device.
"""
from .canonical import digest

MODEL_ID = "SEL-RISK"
MODEL_VERSION = "1.0.0"
THRESHOLD_HIGH = 6
THRESHOLD_MODERATE = 4

# (field, predicate, points, human label, category)
RULES = [
    ("age", lambda p: p["age"] >= 60, 2, "Age 60 or over", "clinical"),
    ("age", lambda p: 50 <= p["age"] < 60, 1, "Age 50 to 59", "clinical"),
    ("family_history", lambda p: p["family_history"], 3, "Family history of the screened condition", "clinical"),
    ("variant_flag", lambda p: p["variant_flag"], 4, "Reported pathogenic variant flag", "genomic"),
    ("years_since_screen", lambda p: p["years_since_screen"] >= 5, 2, "No screening in 5 years or more", "pathway"),
    ("years_since_screen", lambda p: 3 <= p["years_since_screen"] < 5, 1, "Screening gap of 3 to 4 years", "pathway"),
    ("smoker", lambda p: p["smoker"], 1, "Current smoker", "clinical"),
    ("area_decile", lambda p: p["area_decile"] <= 3, 1, "Low area-level socioeconomic decile (access factor, not biology)", "equity"),
]


def assess(person):
    """Return the full reason chain, score, tier and the input digest."""
    reasons = []
    score = 0
    for field, predicate, points, label, category in RULES:
        if predicate(person):
            score += points
            reasons.append({
                "factor": field,
                "label": label,
                "category": category,
                "points": points,
                "observed": person[field],
            })
    if score >= THRESHOLD_HIGH:
        tier = "HIGH"
    elif score >= THRESHOLD_MODERATE:
        tier = "MODERATE"
    else:
        tier = "LOW"
    inputs = {k: person[k] for k in
              ("age", "sex", "family_history", "variant_flag", "years_since_screen", "smoker", "area_decile")}
    return {
        "tier": tier,
        "score": score,
        "reasons": reasons,
        "inputs": inputs,
        "inputs_digest": digest(inputs),
        "model_id": MODEL_ID,
        "model_version": MODEL_VERSION,
        "threshold_high": THRESHOLD_HIGH,
        "threshold_moderate": THRESHOLD_MODERATE,
    }
