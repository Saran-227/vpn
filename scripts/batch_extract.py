#!/usr/bin/env python3
"""Batch Flow-Feature Extractor & Dataset Orchestration Layer.

Processes all PCAP/PCAPNG captures in an input directory using the existing
feature extraction pipeline, validates every flow and capture against strict
consistency rules, performs independent TShark packet cross-validation, and
combines validated flows into standard CSV outputs.
"""

import argparse
import csv
from dataclasses import asdict, fields, replace
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
from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.features import FlowFeatures
from analyzer.feature_extractor.feature_extractor import (
    extract_features_from_packets,
    extract_flow_features,
)
from analyzer.feature_extractor.exporter import export_features_to_csv


FEATURE_FIELDNAMES = [field.name for field in fields(FlowFeatures)]


def discover_pcaps(input_dir: Path) -> List[Path]:
    """Recursively discover all .pcap and .pcapng files in directory."""
    patterns = ["*.pcapng", "*.pcap", "*.PCAPNG", "*.PCAP"]
    found: List[Path] = []
    for pattern in patterns:
        found.extend(input_dir.rglob(pattern))
    # Deduplicate while preserving sorted order
    unique_paths = sorted(list({p.resolve(): p for p in found}.values()))
    return unique_paths


def load_metadata(json_path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON metadata matching capture if present."""
    if not json_path.exists() or not json_path.is_file():
        return None
    try:
        with json_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def run_tshark_count(pcap_path: Path) -> Optional[int]:
    """Independently determine packet count using TShark if installed."""
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        return None
    try:
        cmd = [tshark_bin, "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            lines = [line for line in result.stdout.strip().splitlines() if line.strip()]
            return len(lines)
    except Exception:
        pass
    return None


def validate_flow(f: FlowFeatures) -> List[str]:
    """Validate a single FlowFeatures record against rules A through K."""
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

    # Rule E: packets_per_second calculation consistency
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

    # Rule F: bytes_per_second calculation consistency
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
    numeric_fields = [
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
    for field_name in numeric_fields:
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
    use_tshark: bool = True,
) -> Tuple[List[FlowFeatures], Dict[str, Any]]:
    """Process a single PCAPNG file, returning extracted FlowFeatures and report record."""
    capture_id = pcap_path.stem
    report_entry: Dict[str, Any] = {
        "capture_id": capture_id,
        "pcap_file": pcap_path.name,
        "pcap_path": str(pcap_path),
        "status": "FAILED",
        "packet_count": 0,
        "flow_count": 0,
        "tshark_packet_count": None,
        "validation_status": "SKIPPED",
        "validation_errors": "",
        "error_message": "",
    }

    try:
        # 1. Independent TShark cross-validation
        if use_tshark:
            report_entry["tshark_packet_count"] = run_tshark_count(pcap_path)

        # 2. Read packets with existing reader
        packets = list(read_pcap(pcap_path))
        report_entry["packet_count"] = len(packets)

        # 3. Build flows and extract features
        features = extract_features_from_packets(packets)
        report_entry["flow_count"] = len(features)

        # 4. Validate each flow
        all_val_errors: List[str] = []
        for feat in features:
            flow_errors = validate_flow(feat)
            if flow_errors:
                all_val_errors.extend([f"[{feat.flow_id}] {e}" for e in flow_errors])

        if all_val_errors:
            report_entry["validation_status"] = "FAILED"
            report_entry["validation_errors"] = "; ".join(all_val_errors)
        else:
            report_entry["validation_status"] = "PASSED"
            report_entry["status"] = "SUCCESS"

        return features, report_entry

    except Exception as exc:
        report_entry["status"] = "FAILED"
        report_entry["error_message"] = str(exc)
        return [], report_entry


def compute_dataset_statistics(features: List[FlowFeatures]) -> Dict[str, Dict[str, float]]:
    """Calculate min, max, mean, median, standard deviation for 17 numeric ML features."""
    numeric_fields = [
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

    stats: Dict[str, Dict[str, float]] = {}
    if not features:
        return stats

    for field_name in numeric_fields:
        vals = [float(getattr(f, field_name)) for f in features]
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


def run_batch_extraction(
    input_dir: Path,
    output_dir: Path,
    use_tshark: bool = True,
    save_per_capture: bool = True,
    save_metadata_joined: bool = True,
) -> Dict[str, Any]:
    """Execute complete batch extraction workflow."""
    output_dir.mkdir(parents=True, exist_ok=True)
    per_capture_dir = output_dir / "per_capture"
    if save_per_capture:
        per_capture_dir.mkdir(parents=True, exist_ok=True)

    pcaps = discover_pcaps(input_dir)
    print(f"Discovered {len(pcaps)} PCAP/PCAPNG capture files in {input_dir}")

    all_combined_features: List[FlowFeatures] = []
    metadata_joined_rows: List[Dict[str, Any]] = []
    processing_reports: List[Dict[str, Any]] = []
    failed_captures: List[Dict[str, Any]] = []

    successful_count = 0
    failed_count = 0
    total_packets = 0

    for i, pcap_path in enumerate(pcaps, start=1):
        print(f"[{i}/{len(pcaps)}] Processing {pcap_path.name}...", end=" ", flush=True)
        features, report = process_capture(pcap_path, use_tshark=use_tshark)
        processing_reports.append(report)

        if report["status"] == "SUCCESS":
            successful_count += 1
            total_packets += report["packet_count"]
            print(f"OK ({report['packet_count']} pkts, {len(features)} flows)")

            # Save individual capture CSV if requested
            if save_per_capture:
                cap_csv_path = per_capture_dir / f"{pcap_path.stem}_features.csv"
                export_features_to_csv(features, cap_csv_path)

            # Assign globally unique and traceable flow_id for batch combined dataset
            capture_stem = pcap_path.stem
            for feat in features:
                traceable_flow_id = f"{capture_stem}_{feat.flow_id}"
                combined_feat = replace(feat, flow_id=traceable_flow_id)
                all_combined_features.append(combined_feat)

            # Check for matching JSON metadata for optional joined dataset
            if save_metadata_joined:
                json_path = pcap_path.with_suffix(".json")
                meta = load_metadata(json_path)
                for feat in features:
                    row_dict = {field.name: getattr(feat, field.name) for field in fields(FlowFeatures)}
                    row_dict["flow_id"] = f"{capture_stem}_{feat.flow_id}"
                    row_dict["capture_id"] = capture_stem
                    row_dict["source_pcap"] = pcap_path.name
                    if meta:
                        row_dict["experiment_name"] = meta.get("experiment_name", "")
                        row_dict["traffic_class"] = meta.get("traffic_profile", {}).get("primary_class", "")
                        row_dict["operating_mode"] = meta.get("protocol_stack", {}).get("operating_mode", "")
                        row_dict["ipsec_protocol"] = meta.get("protocol_stack", {}).get("ipsec_protocol", "")
                        row_dict["ike_version"] = meta.get("protocol_stack", {}).get("ike_version", "")
                        row_dict["esp_encryption"] = meta.get("crypto_suite", {}).get("esp_encryption", "")
                        row_dict["nist_compliance"] = meta.get("nist_sp800_77_compliance", {}).get("status", "")
                    metadata_joined_rows.append(row_dict)
        else:
            failed_count += 1
            print(f"FAILED: {report['error_message'] or report['validation_errors']}")
            failed_captures.append(
                {
                    "capture_id": report["capture_id"],
                    "pcap_file": report["pcap_file"],
                    "pcap_path": report["pcap_path"],
                    "error_message": report["error_message"] or report["validation_errors"],
                }
            )

    # 1. Export all_flow_features.csv (Exact 23-column standard schema)
    combined_csv_path = output_dir / "all_flow_features.csv"
    export_features_to_csv(all_combined_features, combined_csv_path)

    # 2. Export processing_report.csv
    report_csv_path = output_dir / "processing_report.csv"
    report_fieldnames = [
        "capture_id",
        "pcap_file",
        "pcap_path",
        "status",
        "packet_count",
        "flow_count",
        "tshark_packet_count",
        "validation_status",
        "validation_errors",
        "error_message",
    ]
    with report_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=report_fieldnames)
        writer.writeheader()
        writer.writerows(processing_reports)

    # 3. Export failed_captures.csv
    failed_csv_path = output_dir / "failed_captures.csv"
    failed_fieldnames = ["capture_id", "pcap_file", "pcap_path", "error_message"]
    with failed_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=failed_fieldnames)
        writer.writeheader()
        writer.writerows(failed_captures)

    # 4. Optional metadata joined dataset
    if save_metadata_joined and metadata_joined_rows:
        meta_csv_path = output_dir / "flow_features_with_metadata.csv"
        meta_fieldnames = list(metadata_joined_rows[0].keys())
        with meta_csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=meta_fieldnames)
            writer.writeheader()
            writer.writerows(metadata_joined_rows)

    stats = compute_dataset_statistics(all_combined_features)

    summary = {
        "total_files": len(pcaps),
        "successful_files": successful_count,
        "failed_files": failed_count,
        "total_flows": len(all_combined_features),
        "total_packets": total_packets,
        "combined_csv": str(combined_csv_path),
        "report_csv": str(report_csv_path),
        "failed_csv": str(failed_csv_path),
        "statistics": stats,
    }

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Batch extract flow features from PCAP/PCAPNG dataset."
    )
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        default="raw_pcapng",
        help="Path to input PCAP/PCAPNG directory (default: raw_pcapng)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="extracted_data",
        help="Path to output directory (default: extracted_data)",
    )
    parser.add_argument(
        "--no-tshark",
        action="store_true",
        help="Disable independent TShark validation",
    )
    parser.add_argument(
        "--no-per-capture",
        action="store_true",
        help="Do not save individual per-capture CSV files",
    )
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Do not export optional metadata-joined CSV",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Error: Input directory does not exist: {input_path}")
        sys.exit(1)

    print("=" * 60)
    print("AI-Powered IPsec VPN Analyzer — Batch Feature Extractor")
    print("=" * 60)
    print(f"Input Directory:  {input_path.resolve()}")
    print(f"Output Directory: {output_path.resolve()}")
    print(f"TShark Check:     {'Disabled' if args.no_tshark else 'Enabled'}")
    print("=" * 60)

    summary = run_batch_extraction(
        input_dir=input_path,
        output_dir=output_path,
        use_tshark=not args.no_tshark,
        save_per_capture=not args.no_per_capture,
        save_metadata_joined=not args.no_metadata,
    )

    print("\n" + "=" * 60)
    print("BATCH EXTRACTION COMPLETE — SUMMARY REPORT")
    print("=" * 60)
    print(f"Total PCAPNG captures discovered: {summary['total_files']}")
    print(f"Successfully processed captures:   {summary['successful_files']}")
    print(f"Failed captures:                   {summary['failed_files']}")
    print(f"Total packets extracted:           {summary['total_packets']}")
    print(f"Total flows extracted:             {summary['total_flows']}")
    print(f"Combined Feature CSV:              {summary['combined_csv']}")
    print(f"Processing Report CSV:             {summary['report_csv']}")
    print(f"Failed Captures CSV:               {summary['failed_csv']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
