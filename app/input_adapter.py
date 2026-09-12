from typing import Dict, Any

from app.models.schemas import StandardFeatures


STANDARD_FEATURE_DEFAULTS = {
    "flow_duration": 0.0,
    "packet_count": 0,
    "bytes_sent": 0,
    "bytes_received": 0,
    "avg_packet_size": 0.0,
    "packets_per_second": 0.0,
    "bytes_per_second": 0.0,
    "tcp_connections": 0,
    "udp_connections": 0,
}


def normalize_features(raw_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert raw network/flow features into the standardized
    feature format expected by the Security Assessment Engine.

    Required standard features are added with default values
    when they are missing.

    Unknown features are preserved so that information is not
    unnecessarily lost during future integration with Asim.
    """

    if not isinstance(raw_features, dict):
        raise TypeError("raw_features must be a dictionary.")

    normalized = dict(raw_features)

    for feature, default_value in STANDARD_FEATURE_DEFAULTS.items():
        if feature not in normalized:
            normalized[feature] = default_value

    return normalized


def create_standard_features(
    raw_features: Dict[str, Any]
) -> StandardFeatures:
    """
    Convert raw features into a StandardFeatures object.

    This provides a clear interface between the input adapter
    and the Security Assessment Engine.
    """

    normalized = normalize_features(raw_features)

    return StandardFeatures(
        flow_duration=normalized["flow_duration"],
        packet_count=normalized["packet_count"],
        bytes_sent=normalized["bytes_sent"],
        bytes_received=normalized["bytes_received"],
        avg_packet_size=normalized["avg_packet_size"],
        packets_per_second=normalized["packets_per_second"],
        bytes_per_second=normalized["bytes_per_second"],
        tcp_connections=normalized["tcp_connections"],
        udp_connections=normalized["udp_connections"],
    )