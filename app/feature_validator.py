import math
from typing import Dict, Any, List


# Features that must be integers
INTEGER_FEATURES = {
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "tcp_connections",
    "udp_connections",
}


# Features that can contain decimal values
FLOAT_FEATURES = {
    "flow_duration",
    "avg_packet_size",
    "packets_per_second",
    "bytes_per_second",
}


# Every feature currently expected by our engine
REQUIRED_FEATURES = INTEGER_FEATURES | FLOAT_FEATURES


def validate_features(features: Dict[str, Any]) -> List[str]:
    """
    Validate network features before they are passed
    to the Security Assessment Engine.

    Returns:
        A list containing validation errors.

        Empty list = all features are valid.
    """

    errors = []

    # -------------------------------------------------
    # 1. Check that the input is a dictionary
    # -------------------------------------------------

    if not isinstance(features, dict):
        return ["Input features must be a dictionary."]

    # -------------------------------------------------
    # 2. Check for missing features
    # -------------------------------------------------

    missing_features = REQUIRED_FEATURES - features.keys()

    for feature in sorted(missing_features):
        errors.append(f"Missing required feature: {feature}")

    # -------------------------------------------------
    # 3. Validate each feature that is present
    # -------------------------------------------------

    for feature, value in features.items():

        # Ignore unknown features for now.
        # This makes future integration with Asim easier.
        if feature not in REQUIRED_FEATURES:
            continue

        # -------------------------------------------------
        # None is not allowed
        # -------------------------------------------------

        if value is None:
            errors.append(f"{feature} cannot be None.")
            continue

        # -------------------------------------------------
        # Boolean values are technically integers in Python.
        # We don't want True/False as network measurements.
        # -------------------------------------------------

        if isinstance(value, bool):
            errors.append(
                f"{feature} must be a numeric value, not boolean."
            )
            continue

        # -------------------------------------------------
        # Check numeric type
        # -------------------------------------------------

        if not isinstance(value, (int, float)):
            errors.append(
                f"{feature} must be numeric, got {type(value).__name__}."
            )
            continue

        # -------------------------------------------------
        # Check NaN / Infinity
        # -------------------------------------------------

        if isinstance(value, float) and not math.isfinite(value):
            errors.append(
                f"{feature} must be a finite number."
            )
            continue

        # -------------------------------------------------
        # Network measurements cannot be negative
        # -------------------------------------------------

        if value < 0:
            errors.append(
                f"{feature} cannot be negative."
            )
            continue

        # -------------------------------------------------
        # Integer features must actually be integers
        # -------------------------------------------------

        if feature in INTEGER_FEATURES and not isinstance(value, int):
            errors.append(
                f"{feature} must be an integer."
            )

    return errors


def is_valid_features(features: Dict[str, Any]) -> bool:
    """
    Return True when all supplied features pass validation.
    """

    return len(validate_features(features)) == 0