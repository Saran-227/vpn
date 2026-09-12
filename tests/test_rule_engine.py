from app.rule_engine import (
    check_packet_rate,
    check_byte_rate,
    check_tcp_connections,
    check_udp_connections,
    check_flow_duration,
    check_traffic_imbalance,
    evaluate_rules
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


def test_normal_packet_rate():
    findings = check_packet_rate(BASE_FEATURES)

    assert findings == []


def test_high_packet_rate():
    features = BASE_FEATURES.copy()
    features["packets_per_second"] = 1200

    findings = check_packet_rate(features)

    assert len(findings) == 1
    assert findings[0].indicator == "HIGH_PACKET_RATE"
    assert findings[0].severity == "HIGH"
    assert findings[0].score == 25


def test_critical_packet_rate():
    features = BASE_FEATURES.copy()
    features["packets_per_second"] = 5000

    findings = check_packet_rate(features)

    assert len(findings) == 1
    assert findings[0].indicator == "CRITICAL_PACKET_RATE"
    assert findings[0].severity == "CRITICAL"


def test_high_byte_rate():
    features = BASE_FEATURES.copy()
    features["bytes_per_second"] = 5500000

    findings = check_byte_rate(features)

    assert len(findings) == 1
    assert findings[0].indicator == "HIGH_BYTE_RATE"
    assert findings[0].severity == "HIGH"


def test_critical_byte_rate():
    features = BASE_FEATURES.copy()
    features["bytes_per_second"] = 10000000

    findings = check_byte_rate(features)

    assert len(findings) == 1
    assert findings[0].indicator == "CRITICAL_BYTE_RATE"
    assert findings[0].severity == "CRITICAL"


def test_excessive_tcp_connections():
    features = BASE_FEATURES.copy()
    features["tcp_connections"] = 60

    findings = check_tcp_connections(features)

    assert len(findings) == 1
    assert findings[0].indicator == "EXCESSIVE_TCP_CONNECTIONS"


def test_excessive_udp_connections():
    features = BASE_FEATURES.copy()
    features["udp_connections"] = 60

    findings = check_udp_connections(features)

    assert len(findings) == 1
    assert findings[0].indicator == "EXCESSIVE_UDP_CONNECTIONS"


def test_abnormal_flow_duration():
    features = BASE_FEATURES.copy()
    features["flow_duration"] = 7200

    findings = check_flow_duration(features)

    assert len(findings) == 1
    assert findings[0].indicator == "ABNORMAL_FLOW_DURATION"


def test_traffic_imbalance():
    features = BASE_FEATURES.copy()
    features["bytes_sent"] = 1000000
    features["bytes_received"] = 100000

    findings = check_traffic_imbalance(features)

    assert len(findings) == 1
    assert findings[0].indicator == "INBOUND_OUTBOUND_IMBALANCE"


def test_no_traffic_imbalance_when_balanced():
    features = BASE_FEATURES.copy()

    findings = check_traffic_imbalance(features)

    assert findings == []


def test_all_rules_together():
    features = BASE_FEATURES.copy()

    features["packets_per_second"] = 1200
    features["bytes_per_second"] = 5500000
    features["tcp_connections"] = 60
    features["udp_connections"] = 60
    features["flow_duration"] = 7200
    features["bytes_sent"] = 1000000
    features["bytes_received"] = 100000

    findings = evaluate_rules(features)

    indicators = {
        finding.indicator
        for finding in findings
    }

    assert "HIGH_PACKET_RATE" in indicators
    assert "HIGH_BYTE_RATE" in indicators
    assert "EXCESSIVE_TCP_CONNECTIONS" in indicators
    assert "EXCESSIVE_UDP_CONNECTIONS" in indicators
    assert "ABNORMAL_FLOW_DURATION" in indicators
    assert "INBOUND_OUTBOUND_IMBALANCE" in indicators