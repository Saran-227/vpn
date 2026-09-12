from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class StandardFeatures:
    """
    Standardized network/flow features expected by
    the Security Assessment Engine.
    """

    flow_duration: float
    packet_count: int
    bytes_sent: int
    bytes_received: int
    avg_packet_size: float
    packets_per_second: float
    bytes_per_second: float
    tcp_connections: int
    udp_connections: int


@dataclass
class SecurityFinding:
    """
    Represents one security indicator detected by
    the rule engine.
    """

    indicator: str
    severity: str
    score: int
    reason: str


@dataclass
class SecurityAssessment:
    """
    Final structured assessment returned by the engine.
    """

    timestamp: str
    risk_score: int
    risk_level: str
    rule_score: int
    anomaly_score: int
    anomaly_detected: bool
    findings: List[Dict[str, Any]]
    anomaly_indicators: List[Dict[str, Any]]
    threat_matrix: Dict[str, Any]
    score_explanation: str
    summary: str
