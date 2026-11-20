"""Tests for the IsolationForest anomaly detector (deterministic)."""

from ai_engine.anomaly import anomaly_score, get_model, is_anomalous
from ai_engine.features import extract_features
from shared.schemas import LogEvent


def _features(failed_count=0, hour=10, event_type="login_success", user="luffy", new_ip=False):
    event = LogEvent(
        timestamp=f"2026-11-20T{hour:02d}:00:00Z",
        host="kali",
        service="sshd",
        user=user,
        source_ip="192.168.56.20",
        event_type=event_type,
        message="test",
        raw="test",
    )
    context = {
        "failed_counts": {"192.168.56.20": failed_count},
        "known_ips": set() if new_ip else {"192.168.56.20"},
    }
    return extract_features(event, context)


def test_normal_traffic_is_not_anomalous():
    assert not is_anomalous(_features())
    assert not is_anomalous(_features(failed_count=1, hour=14))


def test_extreme_traffic_is_anomalous():
    # 3 a.m., 12 failed logins from a new IP, as root: far from normal.
    features = _features(failed_count=12, hour=3, event_type="failed_login", user="root", new_ip=True)
    assert is_anomalous(features)


def test_extreme_scores_lower_than_normal():
    normal = anomaly_score(_features())
    extreme = anomaly_score(_features(failed_count=12, hour=3, event_type="failed_login", user="root", new_ip=True))
    assert extreme < normal


def test_model_is_deterministic():
    score_first = anomaly_score(_features(failed_count=5, hour=2, event_type="failed_login"))
    # Same process, same cached model: identical score.
    assert anomaly_score(_features(failed_count=5, hour=2, event_type="failed_login")) == score_first
    # A freshly trained model with the same seed scores the same.
    model = get_model()
    assert model.random_state == 42
