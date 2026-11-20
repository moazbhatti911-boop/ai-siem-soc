"""Anomaly detection with scikit-learn IsolationForest.

The model is trained once, at first use, on synthetic *normal* lab traffic:
daytime hours, few or no failed logins, ordinary users. Anything far from
that baseline scores below 0 and counts as anomalous. Training is fully
deterministic (fixed ``random_state`` and a seeded generator), so tests and
the smoke test always see the same scores.

Feature order must match :mod:`ai_engine.features`::

    [failed_logins_from_ip, hour, is_failed_login, is_root, is_sudo, is_new_ip]
"""

import random
from functools import lru_cache

from sklearn.ensemble import IsolationForest

# decision_function() < 0 means "anomaly"; < -0.2 is a strong anomaly.
ANOMALY_THRESHOLD = 0.0
STRONG_ANOMALY_THRESHOLD = -0.2


def _normal_training_rows(n: int = 240, seed: int = 42) -> list[list[float]]:
    """Synthetic normal traffic: daytime, low failure counts, ordinary users."""
    rng = random.Random(seed)
    rows: list[list[float]] = []
    for _ in range(n):
        rows.append(
            [
                float(rng.choice([0, 0, 0, 0, 1])),  # failed logins from this IP
                float(rng.randint(7, 19)),  # hour of day
                float(rng.choice([0, 0, 0, 1])),  # is a failed login
                0.0,  # root user (rare in normal traffic)
                float(rng.choice([0, 0, 0, 1])),  # sudo use
                float(rng.choice([0, 0, 0, 1])),  # new source IP
            ]
        )
    return rows


@lru_cache(maxsize=1)
def get_model() -> IsolationForest:
    """Return the trained IsolationForest (trained once per process)."""
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(_normal_training_rows())
    return model


def anomaly_score(features: list[float]) -> float:
    """IsolationForest decision score for one feature vector (higher = more normal)."""
    return float(get_model().decision_function([features])[0])


def is_anomalous(features: list[float], threshold: float = ANOMALY_THRESHOLD) -> bool:
    """True when the feature vector looks anomalous (score below threshold)."""
    return anomaly_score(features) < threshold
