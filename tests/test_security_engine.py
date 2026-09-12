import pytest

from app.security_engine import SecurityAssessmentEngine


NORMAL_FEATURES = {
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


SUSPICIOUS_FEATURES = {
    "flow_duration": 120,
    "packet_count": 100000,
    "bytes_sent": 6000000,
    "bytes_received": 800000,
    "avg_packet_size": 700,
    "packets_per_second": 1200,
    "bytes_per_second": 5500000,
    "tcp_connections": 60,
    "udp_connections": 5
}


ANOMALOUS_FEATURES = {
    "flow_duration": 60,
    "packet_count": 180000,
    "bytes_sent": 9000000,
    "bytes_received": 200000,
    "avg_packet_size": 70,
    "packets_per_second": 3000,
    "bytes_per_second": 15000000,
    "tcp_connections": 10,
    "udp_connections": 10
}


def test_engine_can_be_created():
    engine = SecurityAssessmentEngine()

    assert engine is not None
    assert engine.name == "IPsec VPN Security Assessment Engine"
    assert engine.version == "1.0.0"


def test_normal_traffic_has_low_risk():
    engine = SecurityAssessmentEngine()

    result = engine.assess(NORMAL_FEATURES)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["anomaly_detected"] is False
    assert result["findings"] == []
    assert result["anomaly_indicators"] == []


def test_suspicious_traffic_is_detected():
    engine = SecurityAssessmentEngine()

    result = engine.assess(SUSPICIOUS_FEATURES)

    assert result["risk_score"] > 0
    assert result["risk_level"] in {
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    assert len(result["findings"]) > 0


def test_anomalous_traffic_is_detected():
    engine = SecurityAssessmentEngine()

    result = engine.assess(ANOMALOUS_FEATURES)

    assert result["risk_score"] > 0
    assert result["anomaly_detected"] is True
    assert result["anomaly_score"] > 0
    assert len(result["anomaly_indicators"]) > 0


def test_result_contains_required_fields():
    engine = SecurityAssessmentEngine()

    result = engine.assess(NORMAL_FEATURES)

    required_fields = {
        "engine",
        "timestamp",
        "risk_score",
        "risk_level",
        "rule_score",
        "anomaly_score",
        "anomaly_detected",
        "findings",
        "anomaly_indicators",
        "score_explanation",
        "summary"
    }

    assert required_fields.issubset(result.keys())


def test_result_is_json_serializable():
    import json

    engine = SecurityAssessmentEngine()

    result = engine.assess(SUSPICIOUS_FEATURES)

    json_output = json.dumps(result)

    assert isinstance(json_output, str)
    assert len(json_output) > 0


def test_invalid_input_raises_error():
    engine = SecurityAssessmentEngine()

    invalid_features = NORMAL_FEATURES.copy()
    invalid_features["packet_count"] = -100

    with pytest.raises(ValueError):
        engine.assess(invalid_features)


def test_none_input_raises_error():
    engine = SecurityAssessmentEngine()

    with pytest.raises(TypeError):
        engine.assess(None)


def test_engine_handles_zero_traffic():
    engine = SecurityAssessmentEngine()

    zero_features = {
        "flow_duration": 0,
        "packet_count": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
        "avg_packet_size": 0,
        "packets_per_second": 0,
        "bytes_per_second": 0,
        "tcp_connections": 0,
        "udp_connections": 0
    }

    result = engine.assess(zero_features)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["anomaly_detected"] is False