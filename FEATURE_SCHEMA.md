# Feature Extraction Schema

## Purpose

The feature extraction pipeline converts packet captures (PCAP/PCAPNG)
into bidirectional network-flow records and extracts observable traffic
statistics from each flow.

The feature extractor describes traffic behavior.

It does not infer IPsec cryptographic or security configuration.

---

## Processing Pipeline

PCAP / PCAPNG
    |
    v
Packet Reader
    |
    v
PacketRecord
    |
    v
Flow Builder
    |
    v
FlowRecord
    |
    v
Feature Extractor
    |
    v
FlowFeatures
    |
    v
CSV Export

---

## Flow Identification

A bidirectional flow is identified using:

- Endpoint IP address
- Endpoint port when available
- Transport/network protocol

The endpoint ordering is canonical, so the same communication is
represented as one flow regardless of packet direction.

For protocols without ports, such as ESP and ICMP, ports are stored as
null values.

---

## ML Feature Set

The following 17 numeric features are the current ML candidate inputs.

| Feature | Type | Description |
|---|---|---|
| packet_count | int | Total number of packets in the flow |
| total_bytes | int | Total captured bytes in the flow |
| flow_duration_seconds | float | Time between first and last packet |
| min_packet_size | int | Smallest captured packet size |
| max_packet_size | int | Largest captured packet size |
| avg_packet_size | float | Mean packet size |
| packet_size_std | float | Standard deviation of packet sizes |
| packets_per_second | float | Packet rate over the flow duration |
| bytes_per_second | float | Byte rate over the flow duration |
| forward_packet_count | int | Packets traveling from canonical endpoint A to B |
| backward_packet_count | int | Packets traveling from canonical endpoint B to A |
| forward_bytes | int | Captured bytes from endpoint A to B |
| backward_bytes | int | Captured bytes from endpoint B to A |
| min_inter_arrival_seconds | float | Minimum packet inter-arrival time |
| max_inter_arrival_seconds | float | Maximum packet inter-arrival time |
| avg_inter_arrival_seconds | float | Mean packet inter-arrival time |
| inter_arrival_std | float | Standard deviation of inter-arrival times |

These features describe observable traffic characteristics such as:

- Traffic volume
- Packet size distribution
- Traffic intensity
- Communication directionality
- Timing behavior
- Flow duration

---

## Metadata Fields

The following fields are exported for identification, debugging,
analysis, and dashboard display.

| Field | Type | Description |
|---|---|---|
| flow_id | string | Unique identifier assigned to the flow |
| src_ip | string | Canonical endpoint A IP address |
| dst_ip | string | Canonical endpoint B IP address |
| src_port | int/null | Canonical endpoint A port when available |
| dst_port | int/null | Canonical endpoint B port when available |
| protocol | string | Detected network/transport protocol |

These fields should not be blindly supplied to an ML model because they
may introduce environment, host, service, or application-specific bias.

---

## Edge Cases

### Empty Packet Capture

An empty packet list produces zero flows.

### One-Way Flow

A flow may contain packets in only one direction.

### Single-Packet Flow

A flow containing one packet is valid.

For a single-packet flow:

- Flow duration is zero.
- Packet rate is zero.
- Byte rate is zero.
- Inter-arrival statistics are zero.

### Retransmissions and Duplicate Packets

Duplicate or retransmitted packets are preserved as captured.

They are not automatically removed because packet repetition can be a
meaningful traffic characteristic.

### Missing Ports

Packets without transport ports are supported.

Examples include:

- ESP
- ICMP
- IP fragments without the transport header

### IPv4 Fragmentation

IPv4 fragments are handled without packet reassembly.

If later fragments do not contain the transport header, their protocol
is identified using the IPv4 protocol number.

Fragments belonging to an existing flow are grouped with that flow.

Packet-level port values remain null when the transport header is absent.

### Non-IP Packets

Packets without source and destination IP addresses are not included in
flow construction.

### Malformed PCAP

Invalid PCAP/PCAPNG input raises a ValueError instead of causing an
unhandled parser failure.

---

## Zero-Duration Flows

When a flow contains only one timestamp or all packets share the same
timestamp:

    packets_per_second = 0
    bytes_per_second = 0

This prevents division-by-zero and ensures finite feature values.

---

## Feature Validity Requirements

Generated numeric features should be:

- Finite
- Non-negative where applicable
- Deterministic for the same packet sequence

The exporter must preserve a stable column order.

---

## IPsec Security Boundary

The feature extractor does not determine:

- Encryption algorithm
- Encryption key size
- Authentication method
- Diffie-Hellman group
- Perfect Forward Secrecy
- IKE version
- Security Association lifetime
- Replay-window configuration
- Tunnel or transport security configuration

These properties require separate IPsec/IKE negotiation or configuration
analysis.

Encrypted ESP payloads must not be used to guess cryptographic
configuration.

---

## Current CSV Schema

The exported CSV contains exactly 23 columns in this order:

1. flow_id
2. src_ip
3. dst_ip
4. src_port
5. dst_port
6. protocol
7. packet_count
8. total_bytes
9. flow_duration_seconds
10. min_packet_size
11. max_packet_size
12. avg_packet_size
13. packet_size_std
14. packets_per_second
15. bytes_per_second
16. forward_packet_count
17. backward_packet_count
18. forward_bytes
19. backward_bytes
20. min_inter_arrival_seconds
21. max_inter_arrival_seconds
22. avg_inter_arrival_seconds
23. inter_arrival_std

---

## Testing Status

The feature extraction pipeline currently has 50 passing tests.

The test suite covers:

- Packet parsing
- TCP
- UDP
- ICMP
- ESP
- IKE UDP/500
- NAT-T UDP/4500
- IPv6
- One-way flows
- Single-packet flows
- Retransmissions
- Duplicate packets
- Multiple simultaneous flows
- Missing ports
- Non-IP packets
- Malformed PCAP input
- IPv4 fragmentation
- CSV export
- Feature validity
- End-to-end PCAP analysis
