import csv
from dataclasses import fields, replace
from pathlib import Path
import tempfile
import unittest

from scapy.all import IP, TCP, UDP, Raw, wrpcap

from analyzer.feature_extractor.features import FlowFeatures
from analyzer.feature_extractor.packet_reader import PacketRecord, read_pcap
from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.feature_extractor import (
    extract_features_from_packets,
    extract_flow_features,
)
from scripts.batch_extract import (
    discover_pcaps,
    load_metadata,
    validate_flow,
    process_capture,
    compute_dataset_statistics,
    run_batch_extraction,
)


class TestBatchExtract(unittest.TestCase):
    """Test suite for batch flow-feature extraction orchestration and validation."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        self.input_dir = self.base_path / "raw"
        self.output_dir = self.base_path / "out"
        self.input_dir.mkdir()
        self.output_dir.mkdir()

    def tearDown(self):
        self.test_dir.cleanup()

    def _create_synthetic_pcap(self, pcap_path: Path, flow_specs: list[tuple[str, str, int, int, str, int]]):
        """Helper to create synthetic PCAPs with customizable flows."""
        packets = []
        base_time = 1700000000.0
        for src_ip, dst_ip, sport, dport, proto, count in flow_specs:
            for i in range(count):
                time_val = base_time + (i * 0.1)
                if proto == "TCP":
                    pkt = (
                        IP(src=src_ip, dst=dst_ip)
                        / TCP(sport=sport, dport=dport)
                        / Raw(load=b"X" * 100)
                    )
                elif proto == "UDP":
                    pkt = (
                        IP(src=src_ip, dst=dst_ip)
                        / UDP(sport=sport, dport=dport)
                        / Raw(load=b"Y" * 100)
                    )
                else:
                    pkt = IP(src=src_ip, dst=dst_ip) / Raw(load=b"Z" * 100)
                pkt.time = time_val
                packets.append(pkt)
        wrpcap(str(pcap_path), packets)

    def test_empty_directory(self):
        """Test batch extraction on an empty directory."""
        summary = run_batch_extraction(
            input_dir=self.input_dir,
            output_dir=self.output_dir,
            use_tshark=False,
        )
        self.assertEqual(summary["total_files"], 0)
        self.assertEqual(summary["successful_files"], 0)
        self.assertEqual(summary["failed_files"], 0)
        self.assertEqual(summary["total_flows"], 0)
        self.assertTrue((self.output_dir / "all_flow_features.csv").exists())
        self.assertTrue((self.output_dir / "processing_report.csv").exists())
        self.assertTrue((self.output_dir / "failed_captures.csv").exists())

    def test_single_flow_capture(self):
        """Test capture containing exactly one flow."""
        pcap_path = self.input_dir / "single_flow.pcap"
        self._create_synthetic_pcap(
            pcap_path,
            [("192.168.1.10", "192.168.1.20", 5000, 80, "TCP", 5)],
        )

        features, report = process_capture(pcap_path, use_tshark=False)
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["packet_count"], 5)
        self.assertEqual(len(features), 1)
        self.assertEqual(features[0].packet_count, 5)

    def test_multiple_flows_capture(self):
        """Test capture containing multiple distinct flows."""
        pcap_path = self.input_dir / "multi_flow.pcap"
        self._create_synthetic_pcap(
            pcap_path,
            [
                ("10.0.0.1", "10.0.0.2", 500, 500, "UDP", 4),
                ("10.0.0.1", "10.0.0.2", 4500, 4500, "UDP", 6),
                ("10.0.0.1", "10.0.0.3", 80, 8080, "TCP", 3),
            ],
        )

        features, report = process_capture(pcap_path, use_tshark=False)
        self.assertEqual(report["status"], "SUCCESS")
        self.assertEqual(report["packet_count"], 13)
        self.assertEqual(len(features), 3)

    def test_multiple_pcapng_files(self):
        """Test batch extraction across multiple PCAP files."""
        for i in range(3):
            pcap_path = self.input_dir / f"capture_{i}.pcap"
            self._create_synthetic_pcap(
                pcap_path,
                [("10.0.1.1", f"10.0.1.{10+i}", 1000 + i, 80, "TCP", 4)],
            )

        summary = run_batch_extraction(
            input_dir=self.input_dir,
            output_dir=self.output_dir,
            use_tshark=False,
        )
        self.assertEqual(summary["total_files"], 3)
        self.assertEqual(summary["successful_files"], 3)
        self.assertEqual(summary["failed_files"], 0)
        self.assertEqual(summary["total_flows"], 3)
        self.assertEqual(summary["total_packets"], 12)

    def test_invalid_corrupted_pcap_handling(self):
        """Test graceful non-crashing handling and recording of corrupted PCAP."""
        # 1 valid PCAP
        valid_pcap = self.input_dir / "good.pcap"
        self._create_synthetic_pcap(
            valid_pcap,
            [("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 2)],
        )
        # 1 corrupted file
        corrupt_pcap = self.input_dir / "bad.pcapng"
        with corrupt_pcap.open("wb") as f:
            f.write(b"NOT_A_VALID_PCAP_MAGIC_HEADER_DATA_123456789")

        summary = run_batch_extraction(
            input_dir=self.input_dir,
            output_dir=self.output_dir,
            use_tshark=False,
        )
        self.assertEqual(summary["total_files"], 2)
        self.assertEqual(summary["successful_files"], 1)
        self.assertEqual(summary["failed_files"], 1)

        # Verify failed_captures.csv content
        failed_csv = self.output_dir / "failed_captures.csv"
        with failed_csv.open("r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 1)
            self.assertEqual(reader[0]["pcap_file"], "bad.pcapng")

    def test_output_csv_schema_and_23_columns(self):
        """Verify output CSV contains exactly the required 23 columns in exact order."""
        pcap_path = self.input_dir / "test_schema.pcap"
        self._create_synthetic_pcap(
            pcap_path,
            [("10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 3)],
        )

        run_batch_extraction(
            input_dir=self.input_dir,
            output_dir=self.output_dir,
            use_tshark=False,
        )

        csv_path = self.output_dir / "all_flow_features.csv"
        self.assertTrue(csv_path.exists())

        expected_cols = [
            "flow_id",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
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

        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            self.assertEqual(headers, expected_cols)
            self.assertEqual(len(headers), 23)
            row = next(reader)
            self.assertEqual(len(row), 23)

    def test_validation_rule_checks(self):
        """Test individual validation rules A through J."""
        valid_feature = FlowFeatures(
            flow_id="f1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=1000,
            protocol="TCP",
            packet_count=10,
            total_bytes=1000,
            flow_duration_seconds=2.0,
            min_packet_size=100,
            max_packet_size=100,
            avg_packet_size=100.0,
            packet_size_std=0.0,
            packets_per_second=5.0,
            bytes_per_second=500.0,
            forward_packet_count=6,
            backward_packet_count=4,
            forward_bytes=600,
            backward_bytes=400,
            min_inter_arrival_seconds=0.1,
            max_inter_arrival_seconds=0.3,
            avg_inter_arrival_seconds=0.2,
            inter_arrival_std=0.05,
        )

        # Baseline should have 0 errors
        self.assertEqual(validate_flow(valid_feature), [])

        # Rule A violation
        bad_a = replace(valid_feature, forward_packet_count=9)
        self.assertTrue(any("Rule A failed" in e for e in validate_flow(bad_a)))

        # Rule B violation
        bad_b = replace(valid_feature, forward_bytes=999)
        self.assertTrue(any("Rule B failed" in e for e in validate_flow(bad_b)))

        # Rule C violation
        bad_c = replace(valid_feature, flow_duration_seconds=-1.0)
        self.assertTrue(any("Rule C failed" in e for e in validate_flow(bad_c)))

        # Rule D violation
        bad_d = replace(valid_feature, min_packet_size=500)
        self.assertTrue(any("Rule D failed" in e for e in validate_flow(bad_d)))

        # Rule E violation
        bad_e = replace(valid_feature, packets_per_second=99.0)
        self.assertTrue(any("Rule E failed" in e for e in validate_flow(bad_e)))

        # Rule F violation
        bad_f = replace(valid_feature, bytes_per_second=99.0)
        self.assertTrue(any("Rule F failed" in e for e in validate_flow(bad_f)))

        # Rule H (NaN)
        bad_h = replace(valid_feature, avg_packet_size=float("nan"))
        self.assertTrue(any("Rule H failed" in e for e in validate_flow(bad_h)))

        # Rule I (Inf)
        bad_i = replace(valid_feature, bytes_per_second=float("inf"))
        self.assertTrue(any("Rule I failed" in e for e in validate_flow(bad_i)))

        # Rule J (Negative)
        bad_j = replace(valid_feature, total_bytes=-50)
        self.assertTrue(any("Rule J failed" in e for e in validate_flow(bad_j)))

    def test_statistics_calculation(self):
        """Test computation of min, max, mean, median, std for 17 numeric features."""
        f1 = FlowFeatures(
            flow_id="f1", src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2, protocol="TCP",
            packet_count=10, total_bytes=1000, flow_duration_seconds=1.0,
            min_packet_size=100, max_packet_size=100, avg_packet_size=100.0, packet_size_std=0.0,
            packets_per_second=10.0, bytes_per_second=1000.0,
            forward_packet_count=10, backward_packet_count=0, forward_bytes=1000, backward_bytes=0,
            min_inter_arrival_seconds=0.1, max_inter_arrival_seconds=0.1, avg_inter_arrival_seconds=0.1, inter_arrival_std=0.0,
        )
        f2 = replace(f1, flow_id="f2", packet_count=20, total_bytes=2000, packets_per_second=20.0, bytes_per_second=2000.0)

        stats = compute_dataset_statistics([f1, f2])
        self.assertEqual(stats["packet_count"]["min"], 10.0)
        self.assertEqual(stats["packet_count"]["max"], 20.0)
        self.assertEqual(stats["packet_count"]["mean"], 15.0)
        self.assertEqual(stats["packet_count"]["median"], 15.0)
        self.assertAlmostEqual(stats["packet_count"]["std"], 5.0)


if __name__ == "__main__":
    unittest.main()
