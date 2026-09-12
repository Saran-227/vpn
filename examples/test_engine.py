import json

from app.security_engine import SecurityAssessmentEngine


# ---------------------------------------------------------
# Features extracted from the PCAP
# ---------------------------------------------------------

features = {
    "packets_per_second": 40.78543640061586,
    "bytes_per_second": 13107.212775867607,
    "tcp_connections": 0,
    "udp_connections": 2,
    "flow_duration": 10.273274898529053,
    "packet_count": 419,
    "bytes_sent": 125494,
    "bytes_received": 5394,
    "avg_packet_size": 321.37
}


# ---------------------------------------------------------
# Run Security Assessment Engine
# ---------------------------------------------------------

engine = SecurityAssessmentEngine()

assessment = engine.assess(features)


# ---------------------------------------------------------
# Display result
# ---------------------------------------------------------

print("\n========================================")
print("       SECURITY ASSESSMENT RESULT")
print("========================================")

print(
    json.dumps(
        assessment,
        indent=4
    )
)