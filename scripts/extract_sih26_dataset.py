#!/usr/bin/env python3
"""AI-Powered IPsec VPN Protocol Analyzer — SIH 2026 Dataset Feature Extraction Layer.

Extracts flow-level features from the real communication PCAP dataset in `sih26-dataset/`
using the existing validated feature extraction pipeline, validates flows and captures,
cross-verifies with TShark, and generates standard CSV + JSON datasets.
"""

import argparse
import csv
from dataclasses import fields
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.feature_extractor.packet_reader import read_pcap
from analyzer.feature_extractor.features import FlowFeatures
from analyzer.feature_extractor.feature_extractor import extract_features_from_packets

# Core 23 extractor feature column names in exact schema order
CORE_FEATURE_FIELDNAMES = [field.name for field in fields(FlowFeatures)]

# 17 numeric ML feature names
NUMERIC_ML_FEATURES = [
    "packet_count",
    "total_bytes",
    "flow_duration_seconds",
    "min_packet_size",
    "max_packet_size",
    "avg_packet_size",
    "packet_size_std",
    "packets_per_second",
    "bytes_per_second",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "min_inter_arrival_seconds",
    "max_inter_arrival_seconds",
    "avg_inter_arrival_seconds",
    "inter_arrival_std",
]

# Combined dataset columns
DATASET_FIELDNAMES = CORE_FEATURE_FIELDNAMES + [
    "source_pcap",
    "traffic_category",
    "dataset_flow_id",
]


def discover_pcaps(input_dir: Path) -> List[Path]:
    """Recursively discover all .pcap and .pcapng files in directory."""
    patterns = ["*.pcapng", "*.pcap", "*.PCAPNG", "*.PCAP"]
    found: List[Path] = []
    for pattern in patterns:
        found.extend(input_dir.rglob(pattern))
    # Deduplicate while preserving sorted order
    unique_paths = sorted(list({p.resolve(): p for p in found}.values()))
    return unique_paths


def get_traffic_category(pcap_path: Path, root_dir: Path) -> str:
    """Derive traffic category from relative path within dataset root."""
    try:
        rel_path = pcap_path.relative_to(root_dir)
        if len(rel_path.parts) > 1:
            return rel_path.parts[0]
    except ValueError:
        pass
    return "uncategorized"


def run_tshark_count(pcap_path: Path) -> Optional[int]:
    """Independently determine packet count using capinfos or tshark if installed."""
    capinfos_bin = shutil.which("capinfos")
    if capinfos_bin:
        try:
            cmd = [capinfos_bin, "-c", "-M", str(pcap_path)]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "Number of packets:" in line:
                        val_str = line.split(":")[-1].strip()
                        return int(val_str)
        except Exception:
            pass

    tshark_bin = shutil.which("tshark")
    if tshark_bin:
        try:
            cmd = [tshark_bin, "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                check=False,
            )
            if res.returncode == 0:
                lines = [line for line in res.stdout.strip().splitlines() if line.strip()]
                return len(lines)
        except Exception:
            pass

    return None


def validate_flow(f: FlowFeatures) -> List[str]:
    """Validate a single FlowFeatures record against strict consistency rules."""
    errors: List[str] = []

    # Rule A: Forward + backward packet count == total packet count
    if f.forward_packet_count + f.backward_packet_count != f.packet_count:
        errors.append(
            f"Rule A failed: forward_packets ({f.forward_packet_count}) + "
            f"backward_packets ({f.backward_packet_count}) != packet_count ({f.packet_count})"
        )

    # Rule B: Forward + backward bytes == total bytes
    if f.forward_bytes + f.backward_bytes != f.total_bytes:
        errors.append(
            f"Rule B failed: forward_bytes ({f.forward_bytes}) + "
            f"backward_bytes ({f.backward_bytes}) != total_bytes ({f.total_bytes})"
        )

    # Rule C: Flow duration >= 0
    if f.flow_duration_seconds < 0:
        errors.append(f"Rule C failed: flow_duration_seconds < 0 ({f.flow_duration_seconds})")

    # Rule D: min_packet_size <= avg_packet_size <= max_packet_size
    if not (f.min_packet_size <= f.avg_packet_size <= f.max_packet_size):
        errors.append(
            f"Rule D failed: packet size bounds violation: "
            f"{f.min_packet_size} <= {f.avg_packet_size:.2f} <= {f.max_packet_size}"
        )

    # Rule E: packets_per_second consistency
    if f.flow_duration_seconds > 0:
        expected_pps = f.packet_count / f.flow_duration_seconds
        if not math.isclose(f.packets_per_second, expected_pps, rel_tol=1e-4, abs_tol=1e-4):
            errors.append(
                f"Rule E failed: packets_per_second mismatch: "
                f"got {f.packets_per_second:.4f}, expected {expected_pps:.4f}"
            )
    else:
        if f.packets_per_second != 0.0:
            errors.append(
                f"Rule E failed: packets_per_second must be 0.0 for duration 0, got {f.packets_per_second}"
            )

    # Rule F: bytes_per_second consistency
    if f.flow_duration_seconds > 0:
        expected_bps = f.total_bytes / f.flow_duration_seconds
        if not math.isclose(f.bytes_per_second, expected_bps, rel_tol=1e-4, abs_tol=1e-4):
            errors.append(
                f"Rule F failed: bytes_per_second mismatch: "
                f"got {f.bytes_per_second:.4f}, expected {expected_bps:.4f}"
            )
    else:
        if f.bytes_per_second != 0.0:
            errors.append(
                f"Rule F failed: bytes_per_second must be 0.0 for duration 0, got {f.bytes_per_second}"
            )

    # Rule G: min_inter_arrival <= avg_inter_arrival <= max_inter_arrival
    if f.packet_count > 1:
        if not (
            f.min_inter_arrival_seconds <= f.avg_inter_arrival_seconds + 1e-9
            and f.avg_inter_arrival_seconds <= f.max_inter_arrival_seconds + 1e-9
        ):
            errors.append(
                f"Rule G failed: inter-arrival time bounds violation: "
                f"{f.min_inter_arrival_seconds:.6f} <= {f.avg_inter_arrival_seconds:.6f} <= {f.max_inter_arrival_seconds:.6f}"
            )
    else:
        if any(
            x != 0.0
            for x in [
                f.min_inter_arrival_seconds,
                f.max_inter_arrival_seconds,
                f.avg_inter_arrival_seconds,
                f.inter_arrival_std,
            ]
        ):
            errors.append("Rule G failed: single packet flow inter-arrival stats must be 0.0")

    # Rules H, I, J: Numeric feature safety (No NaN, No Inf, Non-negative)
    for field_name in NUMERIC_ML_FEATURES:
        val = getattr(f, field_name)
        if val is None or math.isnan(val):
            errors.append(f"Rule H failed: {field_name} is NaN or None")
        elif math.isinf(val):
            errors.append(f"Rule I failed: {field_name} is infinite ({val})")
        elif val < 0:
            errors.append(f"Rule J failed: {field_name} is negative ({val})")

    return errors


def process_capture(
    pcap_path: Path,
    root_dir: Path,
    use_tshark: bool = True,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Process a single capture, extracting flows with provenance metadata."""
    try:
        rel_pcap = str(pcap_path.relative_to(root_dir))
    except ValueError:
        rel_pcap = pcap_path.name

    category = get_traffic_category(pcap_path, root_dir)
    capture_id = pcap_path.stem

    report_entry: Dict[str, Any] = {
        "capture_id": capture_id,
        "source_pcap": rel_pcap,
        "traffic_category": category,
        "status": "FAILED",
        "packet_count": 0,
        "flow_count": 0,
        "tshark_packet_count": None,
        "tshark_match": None,
        "validation_status": "SKIPPED",
        "validation_errors": "",
        "error_message": "",
    }

    try:
        # Independent TShark/capinfos count
        if use_tshark:
            tshark_count = run_tshark_count(pcap_path)
            report_entry["tshark_packet_count"] = tshark_count

        # Read packets using existing packet_reader
        packets = list(read_pcap(pcap_path))
        report_entry["packet_count"] = len(packets)

        if report_entry["tshark_packet_count"] is not None:
            report_entry["tshark_match"] = (
                report_entry["packet_count"] == report_entry["tshark_packet_count"]
            )

        # Build flows and extract features using existing extractor
        features = extract_features_from_packets(packets)
        report_entry["flow_count"] = len(features)

        # Validate each flow
        all_val_errors: List[str] = []
        flow_records: List[Dict[str, Any]] = []

        for feat in features:
            flow_errors = validate_flow(feat)
            if flow_errors:
                all_val_errors.extend([f"[{feat.flow_id}] {e}" for e in flow_errors])

            # Construct row dict with original 23 columns + metadata
            row: Dict[str, Any] = {
                field_name: getattr(feat, field_name)
                for field_name in CORE_FEATURE_FIELDNAMES
            }
            row["source_pcap"] = rel_pcap
            row["traffic_category"] = category
            row["dataset_flow_id"] = f"{capture_id}_{feat.flow_id}"
            flow_records.append(row)

        if all_val_errors:
            report_entry["validation_status"] = "FAILED"
            report_entry["validation_errors"] = "; ".join(all_val_errors)
        else:
            report_entry["validation_status"] = "PASSED"
            report_entry["status"] = "SUCCESS"

        return flow_records, report_entry

    except Exception as exc:
        report_entry["status"] = "FAILED"
        report_entry["error_message"] = str(exc)
        return [], report_entry


def compute_feature_statistics(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    """Calculate min, max, mean, median, standard deviation for 17 numeric ML features."""
    stats: Dict[str, Dict[str, float]] = {}
    if not records:
        return stats

    for field_name in NUMERIC_ML_FEATURES:
        vals = [float(r[field_name]) for r in records]
        vals_sorted = sorted(vals)
        n = len(vals)
        min_v = vals_sorted[0]
        max_v = vals_sorted[-1]
        mean_v = sum(vals) / n
        if n % 2 == 1:
            median_v = vals_sorted[n // 2]
        else:
            median_v = (vals_sorted[n // 2 - 1] + vals_sorted[n // 2]) / 2.0
        var_v = sum((x - mean_v) ** 2 for x in vals) / n
        std_v = math.sqrt(var_v)
        stats[field_name] = {
            "min": min_v,
            "max": max_v,
            "mean": mean_v,
            "median": median_v,
            "std": std_v,
        }

    return stats


def compute_category_summary(
    reports: List[Dict[str, Any]],
    records: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Compute category-level summary statistics."""
    summary: Dict[str, Dict[str, Any]] = {}

    # Initialize from reports
    for rep in reports:
        cat = rep["traffic_category"]
        if cat not in summary:
            summary[cat] = {
                "capture_count": 0,
                "successful_capture_count": 0,
                "failed_capture_count": 0,
                "flow_count": 0,
                "packet_count": 0,
                "total_bytes": 0,
            }
        summary[cat]["capture_count"] += 1
        if rep["status"] == "SUCCESS":
            summary[cat]["successful_capture_count"] += 1
            summary[cat]["flow_count"] += rep["flow_count"]
            summary[cat]["packet_count"] += rep["packet_count"]
        else:
            summary[cat]["failed_capture_count"] += 1

    # Sum total bytes from successful records
    for rec in records:
        cat = rec.get("traffic_category", "uncategorized")
        if cat in summary:
            summary[cat]["total_bytes"] += int(rec.get("total_bytes", 0))

    return summary


def validate_csv_json_consistency(
    csv_path: Path,
    json_path: Path,
    float_tolerance: float = 1e-6,
) -> Tuple[bool, List[str]]:
    """Validate consistency between exported CSV and JSON files."""
    errors: List[str] = []

    if not csv_path.exists():
        return False, [f"CSV file does not exist: {csv_path}"]
    if not json_path.exists():
        return False, [f"JSON file does not exist: {json_path}"]

    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)

    with json_path.open("r", encoding="utf-8") as f:
        json_rows = json.load(f)

    if not isinstance(json_rows, list):
        return False, [f"JSON root must be a list, got {type(json_rows).__name__}"]

    if len(csv_rows) != len(json_rows):
        errors.append(
            f"Row count mismatch: CSV has {len(csv_rows)} rows, JSON has {len(json_rows)} objects"
        )

    for idx, (csv_row, json_obj) in enumerate(zip(csv_rows, json_rows)):
        for col in DATASET_FIELDNAMES:
            if col not in json_obj:
                errors.append(f"Row {idx}: Key '{col}' missing from JSON object")
                continue

            csv_val = csv_row.get(col, "")
            json_val = json_obj.get(col)

            # Check nulls (e.g. ports for non-TCP/UDP)
            if json_val is None:
                if csv_val != "":
                    errors.append(f"Row {idx}, '{col}': Expected empty in CSV for null, got '{csv_val}'")
            elif isinstance(json_val, int) and not isinstance(json_val, bool):
                try:
                    c_int = int(csv_val)
                    if c_int != json_val:
                        errors.append(f"Row {idx}, '{col}': Int mismatch: CSV={c_int}, JSON={json_val}")
                except ValueError:
                    errors.append(f"Row {idx}, '{col}': CSV value '{csv_val}' is not int")
            elif isinstance(json_val, float):
                try:
                    c_float = float(csv_val)
                    if not math.isclose(c_float, json_val, rel_tol=float_tolerance, abs_tol=float_tolerance):
                        errors.append(f"Row {idx}, '{col}': Float mismatch: CSV={c_float}, JSON={json_val}")
                except ValueError:
                    errors.append(f"Row {idx}, '{col}': CSV value '{csv_val}' is not float")
            else:
                if str(json_val) != csv_val:
                    errors.append(f"Row {idx}, '{col}': String mismatch: CSV='{csv_val}', JSON='{json_val}'")

    return len(errors) == 0, errors


def write_dataset_readme(
    output_dir: Path,
    summary: Dict[str, Any],
) -> Path:
    """Generate DATASET_README.md documentation file."""
    readme_path = output_dir / "DATASET_README.md"

    cat_table_rows = []
    for cat, data in sorted(summary["category_summary"].items()):
        cat_table_rows.append(
            f"| `{cat}` | {data['capture_count']} | {data['successful_capture_count']} | "
            f"{data['failed_capture_count']} | {data['flow_count']} | {data['packet_count']:,} | "
            f"{data['total_bytes']:,} |"
        )
    cat_table_md = "\n".join(cat_table_rows)

    content = f"""# SIH 2026 IPsec VPN Analyzer — Extracted Flow Feature Dataset

## Overview

This dataset was generated by the **AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework** packet/flow feature extraction layer.

- **Source Dataset Directory**: `{summary['input_directory']}`
- **Total PCAP Captures Discovered**: {summary['total_captures']}
- **Successfully Processed Captures**: {summary['successful_captures']}
- **Failed Captures**: {summary['failed_captures']}
- **Total Flows Extracted**: {summary['total_flows']}
- **Total Packets**: {summary['total_packets']:,}
- **Total Bytes**: {summary['total_bytes']:,}

> [!IMPORTANT]
> **Dataset Labels vs. Inferred Features:**
> The `traffic_category` field is derived strictly from the source directory hierarchy (e.g. `chat/`, `video/`, `bulk_transfer/`) and serves as a dataset-level ground-truth label for machine learning and evaluation. It is **not** a feature inferred by the packet/flow feature extractor.
>
> Furthermore, IPsec cryptographic/security properties (e.g., encryption cipher suites, Diffie-Hellman groups, PFS status, NIST compliance, and security posture ratings) are outside the generic flow feature extractor and are evaluated independently by the IKE/ESP analyzer and security assessment modules.

---

## Dataset Inventory & Category Summary

| Traffic Category | Captures | Successful | Failed | Flows | Packets | Total Bytes |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
{cat_table_md}

---

## Schema & Feature Definitions

The output dataset contains **26 columns**:
- **23 core extractor columns** (6 identity/protocol metadata + 17 numeric ML features)
- **3 dataset-level provenance and label columns**

### Metadata & Identity Columns
1. `flow_id`: Flow identifier generated per capture (`flow_1`, `flow_2`, ...).
2. `src_ip`: Endpoint A IPv4/IPv6 address.
3. `dst_ip`: Endpoint B IPv4/IPv6 address.
4. `src_port`: Endpoint A transport port number (integer, or `null` / empty for non-TCP/UDP).
5. `dst_port`: Endpoint B transport port number (integer, or `null` / empty for non-TCP/UDP).
6. `protocol`: Transport/Network protocol (e.g., `TCP`, `UDP`, `ICMP`, `ESP`, `IPv6`).

### 17 Numeric ML Features
7. `packet_count`: Total number of packets in the bidirectional flow.
8. `total_bytes`: Total byte length of all packets in the flow.
9. `flow_duration_seconds`: Total duration of the flow ($t_{{last}} - t_{{first}}$).
10. `min_packet_size`: Minimum packet size in bytes.
11. `max_packet_size`: Maximum packet size in bytes.
12. `avg_packet_size`: Arithmetic mean of packet sizes in bytes.
13. `packet_size_std`: Population standard deviation of packet sizes.
14. `packets_per_second`: Flow packet throughput rate (0.0 if duration is 0).
15. `bytes_per_second`: Flow byte throughput rate (0.0 if duration is 0).
16. `forward_packet_count`: Packet count in the forward direction ($A \\to B$).
17. `backward_packet_count`: Packet count in the backward direction ($B \\to A$).
18. `forward_bytes`: Byte count in the forward direction ($A \\to B$).
19. `backward_bytes`: Byte count in the backward direction ($B \\to A$).
20. `min_inter_arrival_seconds`: Minimum inter-arrival time between consecutive packets.
21. `max_inter_arrival_seconds`: Maximum inter-arrival time between consecutive packets.
22. `avg_inter_arrival_seconds`: Mean inter-arrival time between consecutive packets.
23. `inter_arrival_std`: Standard deviation of inter-arrival times.

### Dataset Provenance & Label Columns
24. `source_pcap`: Relative path to source PCAP file (e.g. `chat/chat_01.pcap`).
25. `traffic_category`: Directory-derived traffic category label (e.g. `chat`).
26. `dataset_flow_id`: Globally unique flow identifier across the entire dataset (`<capture_stem>_<flow_id>`).

---

## Validation Rules Applied

Every flow record is strictly validated against the following invariants:
- **Rule A (Packet Conservation)**: `forward_packet_count + backward_packet_count == packet_count`
- **Rule B (Byte Conservation)**: `forward_bytes + backward_bytes == total_bytes`
- **Rule C (Non-negative Duration)**: `flow_duration_seconds >= 0.0`
- **Rule D (Packet Size Bounds)**: `min_packet_size <= avg_packet_size <= max_packet_size`
- **Rule E (Packet Rate Consistency)**: `packets_per_second == packet_count / duration` (when duration > 0)
- **Rule F (Byte Rate Consistency)**: `bytes_per_second == total_bytes / duration` (when duration > 0)
- **Rule G (Inter-Arrival Bounds)**: `min_inter_arrival <= avg_inter_arrival <= max_inter_arrival`
- **Rules H, I, J (Numeric Safety)**: No `NaN`, no `Infinite`, no negative values in numeric ML features.
- **TShark / Capinfos Independent Verification**: Packet counts are independently verified against Wireshark/TShark tooling.

---

## Output Artifacts

The generated dataset directory contains:
- `all_flow_features.csv`: Full flow dataset in RFC 4180 CSV format.
- `all_flow_features.json`: Full flow dataset in standard typed JSON array-of-objects format.
- `processing_report.csv`: Capture-by-capture processing and validation report.
- `failed_captures.csv`: Registry of any failed captures and error diagnostics.
- `dataset_summary.json`: Machine-readable summary with feature distribution statistics.
- `DATASET_README.md`: This documentation file.

---

## How to Rerun Extraction

To regenerate this dataset from the project root:

```bash
python scripts/extract_sih26_dataset.py --input sih26-dataset --output extracted_data/sih26_dataset
```

Options:
- `--input <path>`: Source dataset directory (default: `sih26-dataset`)
- `--output <path>`: Destination directory (default: `extracted_data/sih26_dataset`)
- `--no-tshark`: Skip independent TShark packet count cross-verification.
"""
    with readme_path.open("w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")

    return readme_path


def run_dataset_extraction(
    input_dir: Path,
    output_dir: Path,
    use_tshark: bool = True,
) -> Dict[str, Any]:
    """Execute complete dataset extraction workflow and write all artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)

    pcaps = discover_pcaps(input_dir)
    print(f"Discovered {len(pcaps)} PCAP/PCAPNG capture files in {input_dir}")

    all_records: List[Dict[str, Any]] = []
    processing_reports: List[Dict[str, Any]] = []
    failed_captures: List[Dict[str, Any]] = []

    successful_count = 0
    failed_count = 0
    total_packets = 0
    total_bytes = 0
    tshark_mismatches = 0

    for i, pcap_path in enumerate(pcaps, start=1):
        rel_name = (
            str(pcap_path.relative_to(input_dir))
            if pcap_path.is_relative_to(input_dir)
            else pcap_path.name
        )
        print(f"[{i:02d}/{len(pcaps):02d}] Processing {rel_name}...", end=" ", flush=True)

        flow_records, report = process_capture(
            pcap_path=pcap_path,
            root_dir=input_dir,
            use_tshark=use_tshark,
        )
        processing_reports.append(report)

        if report["status"] == "SUCCESS":
            successful_count += 1
            total_packets += report["packet_count"]
            cap_bytes = sum(int(r["total_bytes"]) for r in flow_records)
            total_bytes += cap_bytes
            all_records.extend(flow_records)

            tshark_info = ""
            if report["tshark_packet_count"] is not None:
                if report["tshark_match"]:
                    tshark_info = f", tshark matched ({report['tshark_packet_count']})"
                else:
                    tshark_mismatches += 1
                    tshark_info = f", tshark MISMATCH (python={report['packet_count']}, tshark={report['tshark_packet_count']})"

            print(f"OK ({report['packet_count']:,} pkts, {len(flow_records)} flows{tshark_info})")
        else:
            failed_count += 1
            print(f"FAILED: {report['error_message'] or report['validation_errors']}")
            failed_captures.append(
                {
                    "capture_id": report["capture_id"],
                    "source_pcap": report["source_pcap"],
                    "traffic_category": report["traffic_category"],
                    "error_message": report["error_message"] or report["validation_errors"],
                }
            )

    # 1. Export all_flow_features.csv
    csv_path = output_dir / "all_flow_features.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=DATASET_FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_records)

    # 2. Export all_flow_features.json
    json_path = output_dir / "all_flow_features.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2)
        f.write("\n")

    # 3. Export processing_report.csv
    report_csv_path = output_dir / "processing_report.csv"
    report_fieldnames = [
        "capture_id",
        "source_pcap",
        "traffic_category",
        "status",
        "packet_count",
        "flow_count",
        "tshark_packet_count",
        "tshark_match",
        "validation_status",
        "validation_errors",
        "error_message",
    ]
    with report_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=report_fieldnames)
        writer.writeheader()
        writer.writerows(processing_reports)

    # 4. Export failed_captures.csv
    failed_csv_path = output_dir / "failed_captures.csv"
    failed_fieldnames = [
        "capture_id",
        "source_pcap",
        "traffic_category",
        "error_message",
    ]
    with failed_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=failed_fieldnames)
        writer.writeheader()
        writer.writerows(failed_captures)

    # 5. Validate CSV <-> JSON consistency
    is_consistent, consistency_errors = validate_csv_json_consistency(csv_path, json_path)

    # 6. Compute statistics & summary
    feature_stats = compute_feature_statistics(all_records)
    cat_summary = compute_category_summary(processing_reports, all_records)

    summary_json_path = output_dir / "dataset_summary.json"
    readme_path = output_dir / "DATASET_README.md"

    summary: Dict[str, Any] = {
        "input_directory": str(input_dir.resolve()),
        "output_directory": str(output_dir.resolve()),
        "total_captures": len(pcaps),
        "successful_captures": successful_count,
        "failed_captures": failed_count,
        "total_flows": len(all_records),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "tshark_mismatches": tshark_mismatches,
        "csv_json_consistent": is_consistent,
        "consistency_errors": consistency_errors,
        "category_summary": cat_summary,
        "feature_statistics": feature_stats,
        "output_files": {
            "csv": str(csv_path),
            "json": str(json_path),
            "processing_report": str(report_csv_path),
            "failed_captures": str(failed_csv_path),
            "dataset_summary": str(summary_json_path),
            "readme": str(readme_path),
        },
    }

    # 7. Export dataset_summary.json
    with summary_json_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    # 8. Export DATASET_README.md
    write_dataset_readme(output_dir, summary)

    return summary


def print_summary_report(summary: Dict[str, Any]) -> None:
    """Print standard formatted summary report."""
    print("\n" + "=" * 60)
    print("SIH26 DATASET EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Input directory:      {summary['input_directory']}")
    print(f"Total PCAP/PCAPNG:    {summary['total_captures']}")
    print(f"Successful:           {summary['successful_captures']}")
    print(f"Failed:               {summary['failed_captures']}")
    print(f"Total flows:          {summary['total_flows']}")
    print(f"Total packets:        {summary['total_packets']:,}")
    print(f"Total bytes:          {summary['total_bytes']:,}")
    print(f"Categories:           {len(summary['category_summary'])}")
    print(f"CSV:                  {summary['output_files']['csv']}")
    print(f"JSON:                 {summary['output_files']['json']}")
    print(f"Validation:           {'PASSED' if summary['csv_json_consistent'] and summary['failed_captures'] == 0 else 'CHECK REPORT'}")
    print(f"TShark mismatches:    {summary['tshark_mismatches']}")
    print("=" * 60)

    print("\nCategory-level statistics:")
    print(f"{'traffic_category':<18} | {'captures':<8} | {'flows':<6} | {'packets':<10} | {'bytes':<12}")
    print("-" * 65)
    for cat, data in sorted(summary["category_summary"].items()):
        print(
            f"{cat:<18} | {data['capture_count']:<8} | {data['flow_count']:<6} | "
            f"{data['packet_count']:<10,d} | {data['total_bytes']:<12,d}"
        )
    print("=" * 65)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract flow-level features from sih26-dataset/ and generate CSV + JSON."
    )
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        default="sih26-dataset",
        help="Path to input PCAP/PCAPNG directory (default: sih26-dataset)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="extracted_data/sih26_dataset",
        help="Path to output directory (default: extracted_data/sih26_dataset)",
    )
    parser.add_argument(
        "--no-tshark",
        action="store_true",
        help="Disable independent TShark / capinfos validation",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Error: Input directory does not exist: {input_path}")
        return 1

    summary = run_dataset_extraction(
        input_dir=input_path,
        output_dir=output_path,
        use_tshark=not args.no_tshark,
    )

    print_summary_report(summary)
    return 0 if summary["failed_captures"] == 0 and summary["csv_json_consistent"] else 1


if __name__ == "__main__":
    sys.exit(main())
