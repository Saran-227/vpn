import pytest

from app.input_adapter import (
    normalize_features,
    create_standard_features
)


def test_normalize_features():
    raw_features = {
        "flow_duration": 100,
        "packet_count": 500,
        "bytes_sent": 100000,
        "bytes_received": 90000,
        "avg_packet_size": 400,
        "packets_per_second": 5,
        "bytes_per_second": 1000,
        "tcp_connections": 2,
        "udp_connections": 1
    }

    normalized = normalize_features(raw_features)

    assert normalized["flow_duration"] == 100
    assert normalized["packet_count"] == 500
    assert normalized["bytes_sent"] == 100000
    assert normalized["bytes_received"] == 90000
    assert normalized["avg_packet_size"] == 400
    assert normalized["packets_per_second"] == 5
    assert normalized["bytes_per_second"] == 1000
    assert normalized["tcp_connections"] == 2
    assert normalized["udp_connections"] == 1


def test_missing_features_get_default_values():
    raw_features = {
        "packet_count": 100
    }

    normalized = normalize_features(raw_features)

    assert normalized["packet_count"] == 100
    assert normalized["flow_duration"] == 0.0
    assert normalized["bytes_sent"] == 0
    assert normalized["bytes_received"] == 0


def test_normalize_features_rejects_non_dictionary():
    with pytest.raises(TypeError):
        normalize_features("invalid input")


def test_create_standard_features():
    raw_features = {
        "flow_duration": 120,
        "packet_count": 500,
        "bytes_sent": 100000,
        "bytes_received": 90000,
        "avg_packet_size": 400,
        "packets_per_second": 4.2,
        "bytes_per_second": 833.3,
        "tcp_connections": 2,
        "udp_connections": 1
    }

    features = create_standard_features(raw_features)

    assert features.flow_duration == 120
    assert features.packet_count == 500
    assert features.bytes_sent == 100000
    assert features.bytes_received == 90000
    assert features.tcp_connections == 2
    assert features.udp_connections == 1