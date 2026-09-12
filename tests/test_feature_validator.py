import math

from app.feature_validator import (
    validate_features,
    is_valid_features
)


VALID_FEATURES = {
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


def test_valid_features():
    errors = validate_features(VALID_FEATURES)

    assert errors == []
    assert is_valid_features(VALID_FEATURES) is True


def test_missing_feature():
    features = VALID_FEATURES.copy()

    del features["packet_count"]

    errors = validate_features(features)

    assert "Missing required feature: packet_count" in errors
    assert is_valid_features(features) is False


def test_negative_feature():
    features = VALID_FEATURES.copy()

    features["packet_count"] = -10

    errors = validate_features(features)

    assert "packet_count cannot be negative." in errors
    assert is_valid_features(features) is False


def test_none_value():
    features = VALID_FEATURES.copy()

    features["bytes_sent"] = None

    errors = validate_features(features)

    assert "bytes_sent cannot be None." in errors
    assert is_valid_features(features) is False


def test_boolean_value():
    features = VALID_FEATURES.copy()

    features["tcp_connections"] = True

    errors = validate_features(features)

    assert (
        "tcp_connections must be a numeric value, not boolean."
        in errors
    )


def test_invalid_string_value():
    features = VALID_FEATURES.copy()

    features["bytes_received"] = "90000"

    errors = validate_features(features)

    assert (
        "bytes_received must be numeric, got str."
        in errors
    )


def test_nan_value():
    features = VALID_FEATURES.copy()

    features["packets_per_second"] = math.nan

    errors = validate_features(features)

    assert (
        "packets_per_second must be a finite number."
        in errors
    )


def test_integer_feature_rejects_float():
    features = VALID_FEATURES.copy()

    features["packet_count"] = 500.5

    errors = validate_features(features)

    assert (
        "packet_count must be an integer."
        in errors
    )


def test_non_dictionary_input():
    errors = validate_features("invalid input")

    assert errors == ["Input features must be a dictionary."]