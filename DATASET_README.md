# IPsec VPN Protocol Flow Feature Dataset

## Dataset Overview

This dataset was generated as part of the **AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework** (Packet/Flow Feature Extraction Module). It contains standardized bidirectional network flow features extracted from real IPsec VPN traffic communication experiments.

- **Input Directory**: `raw_pcapng/`
- **Total Input Captures**: 122 `.pcapng` packet capture files (120 experiment runs `exp_001` through `exp_120` + 2 standalone captures).
- **Matching Metadata**: 122 `.json` files detailing experiment configurations and protocol stacks.
- **Total Extracted Flows**: 474 bidirectional network flows.
- **Total Packets Represented**: 19,938 packets.
- **Extraction Status**: 100% Successful (122 / 122 captures processed, 0 failed, 0 validation errors).

---

## Extraction Pipeline Architecture

The feature extraction architecture converts packet captures into bidirectional flow records and statistical features:

```
PCAP / PCAPNG
    │
    ▼
Packet Reader (packet_reader.py)
    │  - Header magic validation
    │  - Layer dissection: IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ESP
    ▼
Flow Builder (flow_builder.py)
    │  - Bidirectional canonical endpoint pairing (IP, Port)
    │  - IP fragment flow grouping
    ▼
Feature Extractor (feature_extractor.py)
    │  - 17 statistical & timing ML features
    │  - Division-by-zero & zero-duration safeguards
    ▼
CSV Export & Orchestration (exporter.py / scripts/batch_extract.py)
```

---

## Feature Schema (23 Columns)

Every row in `all_flow_features.csv` represents **one bidirectional flow** and contains exactly 23 columns in this order:

### 1. Metadata / Identification Fields (6 columns)
1. `flow_id`: Unique traceable identifier (format: `{capture_id}_{flow_id}`)
2. `src_ip`: Canonical endpoint A IP address
3. `dst_ip`: Canonical endpoint B IP address
4. `src_port`: Canonical endpoint A transport port (null for ESP/ICMP)
5. `dst_port`: Canonical endpoint B transport port (null for ESP/ICMP)
6. `protocol`: Network / Transport protocol (TCP, UDP, ICMP, ESP, etc.)

### 2. Numeric ML Candidate Features (17 columns)
7. `packet_count`: Total packets observed in the flow
8. `total_bytes`: Total byte volume across all packets in the flow
9. `flow_duration_seconds`: Time difference between first and last packet (0 for single-packet flows)
10. `min_packet_size`: Smallest packet size (bytes)
11. `max_packet_size`: Largest packet size (bytes)
12. `avg_packet_size`: Mean packet size (bytes)
13. `packet_size_std`: Standard deviation of packet sizes
14. `packets_per_second`: Packet rate over flow duration (0 if duration == 0)
15. `bytes_per_second`: Byte rate over flow duration (0 if duration == 0)
16. `forward_packet_count`: Packets from canonical endpoint A to B
17. `backward_packet_count`: Packets from canonical endpoint B to A
18. `forward_bytes`: Bytes transmitted from endpoint A to B
19. `backward_bytes`: Bytes transmitted from endpoint B to A
20. `min_inter_arrival_seconds`: Minimum packet inter-arrival time (0 for single-packet flows)
21. `max_inter_arrival_seconds`: Maximum packet inter-arrival time (0 for single-packet flows)
22. `avg_inter_arrival_seconds`: Mean packet inter-arrival time (0 for single-packet flows)
23. `inter_arrival_std`: Standard deviation of inter-arrival times (0 for single-packet flows)

---

## Dataset Statistical Profile (17 ML Features)

Summary statistics across all 474 extracted flows:

| Feature | Min | Max | Mean | Median | Std Dev |
|---|---|---|---|---|---|
| `packet_count` | 1.0000 | 838.0000 | 41.3017 | 2.0000 | 135.7508 |
| `total_bytes` | 54.0000 | 832854.0000 | 29873.0738 | 1010.0000 | 131668.0890 |
| `flow_duration_seconds` | 0.0000 | 14.2361 | 2.2413 | 0.0112 | 3.3061 |
| `min_packet_size` | 54.0000 | 626.0000 | 203.3650 | 122.0000 | 170.6390 |
| `max_packet_size` | 54.0000 | 1514.0000 | 354.8143 | 318.0000 | 357.4435 |
| `avg_packet_size` | 54.0000 | 1137.5735 | 273.8834 | 246.6000 | 228.4179 |
| `packet_size_std` | 0.0000 | 615.4710 | 46.2975 | 8.0000 | 102.9282 |
| `packets_per_second` | 0.0000 | 47662.5455 | 486.2041 | 4.3651 | 3239.5024 |
| `bytes_per_second` | 0.0000 | 6386781.0909 | 81657.2644 | 1100.5630 | 407574.0007 |
| `forward_packet_count` | 0.0000 | 824.0000 | 36.4557 | 1.0000 | 133.4642 |
| `backward_packet_count` | 1.0000 | 33.0000 | 4.8460 | 1.0000 | 6.4090 |
| `forward_bytes` | 0.0000 | 824090.0000 | 28307.6287 | 318.0000 | 130370.1506 |
| `backward_bytes` | 54.0000 | 17928.0000 | 1565.4451 | 486.0000 | 2817.1504 |
| `min_inter_arrival_seconds` | 0.0000 | 4.0970 | 0.0208 | 0.0001 | 0.1922 |
| `max_inter_arrival_seconds` | 0.0000 | 4.0970 | 0.4882 | 0.0112 | 0.9170 |
| `avg_inter_arrival_seconds` | 0.0000 | 4.0970 | 0.1438 | 0.0104 | 0.3168 |
| `inter_arrival_std` | 0.0000 | 1.8056 | 0.1542 | 0.0000 | 0.3184 |

---

## Validation Rules Enforced

Every flow and capture is verified against 11 consistency rules:
- **Rule A**: `forward_packet_count + backward_packet_count == packet_count`
- **Rule B**: `forward_bytes + backward_bytes == total_bytes`
- **Rule C**: `flow_duration_seconds >= 0`
- **Rule D**: `min_packet_size <= avg_packet_size <= max_packet_size`
- **Rule E**: `packets_per_second` matches `packet_count / flow_duration_seconds` when `duration > 0` (0 when duration == 0)
- **Rule F**: `bytes_per_second` matches `total_bytes / flow_duration_seconds` when `duration > 0` (0 when duration == 0)
- **Rule G**: `min_inter_arrival_seconds <= avg_inter_arrival_seconds <= max_inter_arrival_seconds` (0 for single-packet flows)
- **Rule H**: No NaN or missing values in required numeric fields (0 NaNs observed)
- **Rule I**: No infinite values (0 Infs observed)
- **Rule J**: Non-negativity constraints for all 17 numeric features
- **Rule K**: Exact 23-column ordering and zero column duplicates

---

## Output Files

All artifacts are generated in `extracted_data/`:

| File | Description |
|---|---|
| `extracted_data/all_flow_features.csv` | **Primary Deliverable**: 474 validated flow records in canonical 23-column schema. |
| `extracted_data/processing_report.csv` | Detailed per-capture execution log (packets, flows, TShark validation, errors). |
| `extracted_data/failed_captures.csv` | Audit log of any failed captures (0 failures on current dataset). |
| `extracted_data/per_capture/` | Directory containing individual feature CSVs for each of the 122 PCAPNG files. |
| `extracted_data/flow_features_with_metadata.csv` | Companion dataset merging JSON experiment labels with extracted flow features for ML training. |

---

## How to Rerun Extraction

To execute batch extraction across the raw dataset:

```bash
# Standard batch extraction with TShark verification
python scripts/batch_extract.py --input raw_pcapng --output extracted_data

# Disable TShark if running in an environment without Wireshark/TShark
python scripts/batch_extract.py --input raw_pcapng --output extracted_data --no-tshark
```

To execute the automated test suite:

```bash
# Run all tests (58 unit and integration tests)
python -m unittest discover -s analyzer/tests
```

---

## Security Boundary & Important Limitations

1. **Generic Traffic Flow Features**: The extracted features represent observable packet timing, packet volume, directionality, and packet size distributions.
2. **No Cryptographic Inference**: The feature extractor does NOT infer encryption algorithms (e.g. AES-128, AES-256, 3DES), hash functions, Diffie-Hellman groups, PFS settings, SA lifetimes, or NIST compliance.
3. **Security Assessment Separation**: Cryptographic analysis, compliance evaluation, and vulnerability scanning are handled independently by the IPsec/IKE protocol analyzer and security assessment engines.
