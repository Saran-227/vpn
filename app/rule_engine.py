import json
from pathlib import Path
from typing import Dict, Any, List

from app.models.schemas import SecurityFinding


# ---------------------------------------------------------
# Configuration paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

THRESHOLDS_PATH = PROJECT_ROOT / "config" / "thresholds.json"
SCORING_PATH = PROJECT_ROOT / "config" / "scoring.json"


# ---------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------

def load_json_config(path: Path) -> Dict[str, Any]:
    """
    Load a JSON configuration file.

    Args:
        path: Path to the JSON configuration file.

    Returns:
        Configuration as a dictionary.
    """

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# Load configurations once when this module is imported.
THRESHOLDS = load_json_config(THRESHOLDS_PATH)
SCORING = load_json_config(SCORING_PATH)


# ---------------------------------------------------------
# Helper function
# ---------------------------------------------------------

def create_finding(
    indicator: str,
    reason: str
) -> SecurityFinding:
    """
    Create a standardized SecurityFinding using the
    severity and score configured for the indicator.
    """

    rule_config = SCORING.get(indicator)

    if rule_config is None:
        raise ValueError(
            f"No scoring configuration found for: {indicator}"
        )

    return SecurityFinding(
        indicator=indicator,
        severity=rule_config["severity"],
        score=rule_config["score"],
        reason=reason
    )


# ---------------------------------------------------------
# Packet-rate rule
# ---------------------------------------------------------

def check_packet_rate(features: Dict[str, Any]) -> List[SecurityFinding]:
    """
    Detect unusually high packet rates.
    """

    findings = []

    packet_rate = features["packets_per_second"]

    critical_threshold = THRESHOLDS["packets_per_second"]["critical"]
    high_threshold = THRESHOLDS["packets_per_second"]["high"]

    if packet_rate >= critical_threshold:

        findings.append(
            create_finding(
                "CRITICAL_PACKET_RATE",
                (
                    f"Packet rate ({packet_rate:.2f} packets/sec) "
                    f"exceeded the critical threshold "
                    f"({critical_threshold} packets/sec)."
                )
            )
        )

    elif packet_rate >= high_threshold:

        findings.append(
            create_finding(
                "HIGH_PACKET_RATE",
                (
                    f"Packet rate ({packet_rate:.2f} packets/sec) "
                    f"exceeded the high threshold "
                    f"({high_threshold} packets/sec)."
                )
            )
        )

    return findings


# ---------------------------------------------------------
# Byte-rate rule
# ---------------------------------------------------------

def check_byte_rate(features: Dict[str, Any]) -> List[SecurityFinding]:
    """
    Detect unusually high byte transmission rates.
    """

    findings = []

    byte_rate = features["bytes_per_second"]

    critical_threshold = THRESHOLDS["bytes_per_second"]["critical"]
    high_threshold = THRESHOLDS["bytes_per_second"]["high"]

    if byte_rate >= critical_threshold:

        findings.append(
            create_finding(
                "CRITICAL_BYTE_RATE",
                (
                    f"Byte rate ({byte_rate:.2f} bytes/sec) "
                    f"exceeded the critical threshold "
                    f"({critical_threshold} bytes/sec)."
                )
            )
        )

    elif byte_rate >= high_threshold:

        findings.append(
            create_finding(
                "HIGH_BYTE_RATE",
                (
                    f"Byte rate ({byte_rate:.2f} bytes/sec) "
                    f"exceeded the high threshold "
                    f"({high_threshold} bytes/sec)."
                )
            )
        )

    return findings


# ---------------------------------------------------------
# TCP connection rule
# ---------------------------------------------------------

def check_tcp_connections(
    features: Dict[str, Any]
) -> List[SecurityFinding]:
    """
    Detect excessive TCP connections.
    """

    findings = []

    connections = features["tcp_connections"]

    high_threshold = THRESHOLDS["tcp_connections"]["high"]

    if connections >= high_threshold:

        findings.append(
            create_finding(
                "EXCESSIVE_TCP_CONNECTIONS",
                (
                    f"TCP connection count ({connections}) "
                    f"exceeded the high threshold "
                    f"({high_threshold})."
                )
            )
        )

    return findings


# ---------------------------------------------------------
# UDP connection rule
# ---------------------------------------------------------

def check_udp_connections(
    features: Dict[str, Any]
) -> List[SecurityFinding]:
    """
    Detect excessive UDP connections.
    """

    findings = []

    connections = features["udp_connections"]

    high_threshold = THRESHOLDS["udp_connections"]["high"]

    if connections >= high_threshold:

        findings.append(
            create_finding(
                "EXCESSIVE_UDP_CONNECTIONS",
                (
                    f"UDP connection count ({connections}) "
                    f"exceeded the high threshold "
                    f"({high_threshold})."
                )
            )
        )

    return findings


# ---------------------------------------------------------
# Flow-duration rule
# ---------------------------------------------------------

def check_flow_duration(
    features: Dict[str, Any]
) -> List[SecurityFinding]:
    """
    Detect unusually long flows.

    Note:
        A long flow is not automatically malicious.
        It is treated only as a potential indicator.
    """

    findings = []

    duration = features["flow_duration"]

    high_threshold = THRESHOLDS["flow_duration"]["high"]

    if duration >= high_threshold:

        findings.append(
            create_finding(
                "ABNORMAL_FLOW_DURATION",
                (
                    f"Flow duration ({duration:.2f} seconds) "
                    f"exceeded the configured high threshold "
                    f"({high_threshold} seconds)."
                )
            )
        )

    return findings


# ---------------------------------------------------------
# Traffic imbalance rule
# ---------------------------------------------------------

def check_traffic_imbalance(
    features: Dict[str, Any]
) -> List[SecurityFinding]:
    """
    Detect significant imbalance between sent and received bytes.

    This is only a behavioral indicator. It does not mean
    that the traffic is malicious by itself.
    """

    findings = []

    bytes_sent = features["bytes_sent"]
    bytes_received = features["bytes_received"]

    # Avoid division by zero.
    if bytes_sent == 0 and bytes_received == 0:
        return findings

    if bytes_received == 0:
        ratio = float("inf")
    elif bytes_sent == 0:
        ratio = float("inf")
    else:
        ratio = max(
            bytes_sent / bytes_received,
            bytes_received / bytes_sent
        )

    high_threshold = THRESHOLDS[
        "traffic_imbalance_ratio"
    ]["high"]

    if ratio >= high_threshold:

        create_reason = (
            f"Sent/received traffic ratio ({ratio:.2f}) "
            f"exceeded the configured high threshold "
            f"({high_threshold})."
        )

        findings.append(
            create_finding(
                "INBOUND_OUTBOUND_IMBALANCE",
                create_reason
            )
        )

    return findings


# ---------------------------------------------------------
# Main rule-engine function
# ---------------------------------------------------------

def evaluate_rules(
    features: Dict[str, Any]
) -> List[SecurityFinding]:
    """
    Run all currently implemented security rules.

    Args:
        features:
            Standardized and validated network features.

    Returns:
        List of detected security findings.
    """

    findings = []

    findings.extend(check_packet_rate(features))
    findings.extend(check_byte_rate(features))
    findings.extend(check_tcp_connections(features))
    findings.extend(check_udp_connections(features))
    findings.extend(check_flow_duration(features))
    findings.extend(check_traffic_imbalance(features))

    return findings