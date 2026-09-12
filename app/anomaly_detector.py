from typing import Dict, Any, List


def calculate_anomaly_indicators(
    features: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Analyze standardized network features and identify
    potentially unusual combinations of behavior.

    This is an explainable rule-based anomaly detector.
    It does NOT claim that anomalous traffic is malicious.

    Returns:
        A list of anomaly indicators.
    """

    indicators = []

    packet_rate = features["packets_per_second"]
    byte_rate = features["bytes_per_second"]
    packet_count = features["packet_count"]
    avg_packet_size = features["avg_packet_size"]
    bytes_sent = features["bytes_sent"]
    bytes_received = features["bytes_received"]

    # ---------------------------------------------------------
    # Indicator 1:
    # High packet rate combined with high byte rate
    # ---------------------------------------------------------

    if packet_rate >= 1000 and byte_rate >= 5_000_000:

        indicators.append(
            {
                "indicator": "HIGH_TRAFFIC_VOLUME",
                "severity": "HIGH",
                "reason": (
                    "Packet rate and byte rate are both "
                    "significantly elevated."
                )
            }
        )

    # ---------------------------------------------------------
    # Indicator 2:
    # Very high packet count during a relatively short flow
    # ---------------------------------------------------------

    flow_duration = features["flow_duration"]

    if (
        flow_duration > 0
        and packet_count / flow_duration >= 1000
    ):

        indicators.append(
            {
                "indicator": "HIGH_PACKET_DENSITY",
                "severity": "HIGH",
                "reason": (
                    "The flow contains a very high number "
                    "of packets relative to its duration."
                )
            }
        )

    # ---------------------------------------------------------
    # Indicator 3:
    # Unusual packet-size behavior
    # ---------------------------------------------------------

    if avg_packet_size > 1500:

        indicators.append(
            {
                "indicator": "LARGE_AVERAGE_PACKET_SIZE",
                "severity": "MEDIUM",
                "reason": (
                    "Average packet size is above the "
                    "configured normal MTU-sized range."
                )
            }
        )

    # ---------------------------------------------------------
    # Indicator 4:
    # Strong inbound/outbound imbalance
    # ---------------------------------------------------------

    if bytes_sent == 0 and bytes_received > 0:
        ratio = float("inf")

    elif bytes_received == 0 and bytes_sent > 0:
        ratio = float("inf")

    elif bytes_sent == 0 and bytes_received == 0:
        ratio = 1

    else:
        ratio = max(
            bytes_sent / bytes_received,
            bytes_received / bytes_sent
        )

    if ratio >= 10:

        indicators.append(
            {
                "indicator": "SEVERE_TRAFFIC_IMBALANCE",
                "severity": "HIGH",
                "reason": (
                    "The ratio between inbound and outbound "
                    "traffic is extremely high."
                )
            }
        )

    # ---------------------------------------------------------
    # Indicator 5:
    # High packet rate but unusually small average packets
    # ---------------------------------------------------------

    if packet_rate >= 1000 and avg_packet_size < 100:

        indicators.append(
            {
                "indicator": "HIGH_RATE_SMALL_PACKETS",
                "severity": "HIGH",
                "reason": (
                    "A high packet rate is combined with "
                    "an unusually small average packet size."
                )
            }
        )

    return indicators


def calculate_anomaly_score(
    anomaly_indicators: List[Dict[str, Any]]
) -> int:
    """
    Calculate an anomaly score from detected anomaly indicators.

    The score is capped at 100.
    """

    severity_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 20,
        "CRITICAL": 30
    }

    score = 0

    for indicator in anomaly_indicators:

        severity = indicator.get("severity", "LOW")

        score += severity_scores.get(severity, 0)

    return min(score, 100)


def detect_anomalies(
    features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Run anomaly detection on standardized network features.

    Returns:
        A structured anomaly assessment.
    """

    indicators = calculate_anomaly_indicators(features)

    anomaly_score = calculate_anomaly_score(indicators)

    return {
        "anomaly_detected": len(indicators) > 0,
        "anomaly_score": anomaly_score,
        "indicators": indicators
    }