from app.anomaly_detector import (
    calculate_anomaly_indicators,
    calculate_anomaly_score,
    detect_anomalies
)


BASE_FEATURES = {
    "flow_duration": 120,
    "packet_count": 500,
    "bytes_sent": 100000,
    "bytes_received": 90000,
    "avg_packet_size": 400,
    "packets_per_second": 5,
    "bytes_per_second": 1000,
    "tcp_connections": 2,
    "udp_connections": 1
}


def test_normal_traffic_has_no_anomalies():
    indicators = calculate_anomaly_indicators(
        BASE_FEATURES
    )

    assert indicators == []


def test_high_traffic_volume():
    features = BASE_FEATURES.copy()

    features["packets_per_second"] = 1200
    features["bytes_per_second"] = 5500000

    indicators = calculate_anomaly_indicators(
        features
    )

    names = {
        indicator["indicator"]
        for indicator in indicators
    }

    assert "HIGH_TRAFFIC_VOLUME" in names


def test_high_packet_density():
    features = BASE_FEATURES.copy()

    features["flow_duration"] = 60
    features["packet_count"] = 100000

    indicators = calculate_anomaly_indicators(
        features
    )

    names = {
        indicator["indicator"]
        for indicator in indicators
    }

    assert "HIGH_PACKET_DENSITY" in names


def test_large_average_packet_size():
    features = BASE_FEATURES.copy()

    features["avg_packet_size"] = 1600

    indicators = calculate_anomaly_indicators(
        features
    )

    names = {
        indicator["indicator"]
        for indicator in indicators
    }

    assert "LARGE_AVERAGE_PACKET_SIZE" in names


def test_severe_traffic_imbalance():
    features = BASE_FEATURES.copy()

    features["bytes_sent"] = 1000000
    features["bytes_received"] = 50000

    indicators = calculate_anomaly_indicators(
        features
    )

    names = {
        indicator["indicator"]
        for indicator in indicators
    }

    assert "SEVERE_TRAFFIC_IMBALANCE" in names


def test_high_rate_small_packets():
    features = BASE_FEATURES.copy()

    features["packets_per_second"] = 1200
    features["avg_packet_size"] = 70

    indicators = calculate_anomaly_indicators(
        features
    )

    names = {
        indicator["indicator"]
        for indicator in indicators
    }

    assert "HIGH_RATE_SMALL_PACKETS" in names


def test_zero_traffic_does_not_create_imbalance():
    features = BASE_FEATURES.copy()

    features["bytes_sent"] = 0
    features["bytes_received"] = 0

    indicators = calculate_anomaly_indicators(
        features
    )

    names = {
        indicator["indicator"]
        for indicator in indicators
    }

    assert "SEVERE_TRAFFIC_IMBALANCE" not in names


def test_anomaly_score_zero_when_no_indicators():
    score = calculate_anomaly_score([])

    assert score == 0


def test_anomaly_score_for_high_severity():
    indicators = [
        {
            "indicator": "TEST",
            "severity": "HIGH",
            "reason": "Test indicator"
        }
    ]

    score = calculate_anomaly_score(indicators)

    assert score == 20


def test_anomaly_score_is_capped_at_100():
    indicators = [
        {
            "indicator": f"TEST_{i}",
            "severity": "CRITICAL",
            "reason": "Test indicator"
        }
        for i in range(10)
    ]

    score = calculate_anomaly_score(indicators)

    assert score == 100


def test_detect_anomalies_returns_complete_result():
    features = BASE_FEATURES.copy()

    features["packets_per_second"] = 1200
    features["bytes_per_second"] = 5500000

    result = detect_anomalies(features)

    assert result["anomaly_detected"] is True
    assert result["anomaly_score"] > 0
    assert len(result["indicators"]) > 0