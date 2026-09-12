import csv
import json
import math
from pathlib import Path
import tempfile
import unittest

from scapy.all import IP, TCP, UDP, Raw, wrpcap

from analyzer.feature_extractor.features import FlowFeatures
from scripts.extract_sih26_dataset import (
    discover_pcaps,
    get_traffic_category,
    validate_flow,
    process_capture,
    compute_feature_statistics,
    compute_category_summary,
    validate_csv_json_consistency,
    run_dataset_extraction,
    CORE_FEATURE_FIELDNAMES,
    DATASET_FIELDNAMES,
    NUMERIC_ML_FEATURES,
)


class TestExtractSih26Dataset(unittest.TestCase):
    """Unit and integration test suite for SIH26 dataset extraction layer."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        self.input_dir = self.base_path / "dataset"
        self.output_dir = self.base_path / "extracted_data"
        self.input_dir.mkdir()
        self.output_dir.mkdir()

    def tearDown(self):
        self.test_dir.cleanup()

    def _create_synthetic_pcap(
        self,
        pcap_path: Path,
        flow_specs: list[tuple[str, str, int, int, str, int]],
    ):
        """Helper to create synthetic PCAPs with customizable flows."""
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        packets = []
        base_time = 1700000000.0
        for src_ip, dst_ip, sport, dport, proto, count in flow_specs:
            for i in range(count):
                time_val = base_time + (i * 0.1)
                if proto == "TCP":
                    pkt = (
                        IP(src=src_ip, dst=dst_ip)
                        / TCP(sport=sport, dport=dport)
                        / Raw(load=b"A" * 100)
                    )
                elif proto == "UDP":
                    pkt = (
                        IP(src=src_ip, dst=dst_ip)
                        / UDP(sport=sport, dport=dport)
                        / Raw(load=b"B" * 100)
                    )
                else:
                    pkt = IP(src=src_ip, dst=dst_ip) / Raw(load=b"C" * 100)
                pkt.time = time_val
                packets.append(pkt)
        wrpcap(str(pcap_path), packets)

    def test_01_recursive_pcap_discovery(self):
        """1. Test recursive discovery of .pcap and .pcapng files across directories."""
        (self.input_dir / "cat_a").mkdir()
        (self.input_dir / "cat_b" / "nested").mkdir(parents=True)

        f1 = self.input_dir / "cat_a" / "test1.pcap"
        f2 = self.input_dir / "cat_b" / "test2.pcapng"
        f3 = self.input_dir / "cat_b" / "nested" / "test3.PCAP"
        f4 = self.input_dir / "ignore.txt"

        self._create_synthetic_pcap(f1, [("10.0.0.1", "10.0.0.2", 80, 1000, "TCP", 2)])
        self._create_synthetic_pcap(f2, [("10.0.0.1", "10.0.0.2", 80, 1000, "TCP", 2)])
        self._create_synthetic_pcap(f3, [("10.0.0.1", "10.0.0.2", 80, 1000, "TCP", 2)])
        f4.write_text("not a pcap")

        discovered = discover_pcaps(self.input_dir)
        self.assertEqual(len(discovered), 3)
        self.assertIn(f1.resolve(), [p.resolve() for p in discovered])
        self.assertIn(f2.resolve(), [p.resolve() for p in discovered])
        self.assertIn(f3.resolve(), [p.resolve() for p in discovered])

    def test_02_category_detection(self):
        """2. Test traffic category extraction from directory structure."""
        pcap1 = self.input_dir / "chat" / "chat_01.pcap"
        pcap2 = self.input_dir / "bulk_transfer" / "sub" / "bulk_01.pcap"
        pcap3 = self.input_dir / "root_file.pcap"

        self.assertEqual(get_traffic_category(pcap1, self.input_dir), "chat")
        self.assertEqual(get_traffic_category(pcap2, self.input_dir), "bulk_transfer")
        self.assertEqual(get_traffic_category(pcap3, self.input_dir), "uncategorized")

    def test_03_multiple_categories(self):
        """3. Test dataset processing across multiple distinct categories."""
        self._create_synthetic_pcap(
            self.input_dir / "chat" / "chat_01.pcap",
            [("10.0.0.1", "10.0.0.2", 4500, 4500, "UDP", 4)],
        )
        self._create_synthetic_pcap(
            self.input_dir / "video" / "video_01.pcap",
            [("10.0.1.1", "10.0.1.2", 5000, 5000, "UDP", 6)],
        )
        self._create_synthetic_pcap(
            self.input_dir / "web" / "web_01.pcap",
            [("10.0.2.1", "10.0.2.2", 80, 50000, "TCP", 8)],
        )

        summary = run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)
        self.assertEqual(summary["total_captures"], 3)
        self.assertEqual(summary["successful_captures"], 3)
        self.assertEqual(len(summary["category_summary"]), 3)
        self.assertIn("chat", summary["category_summary"])
        self.assertIn("video", summary["category_summary"])
        self.assertIn("web", summary["category_summary"])

    def test_04_multiple_pcap_files(self):
        """4. Test processing multiple PCAP files in a single category."""
        for i in range(1, 4):
            self._create_synthetic_pcap(
                self.input_dir / "email" / f"email_0{i}.pcap",
                [("10.1.1.1", f"10.1.1.{i+1}", 25, 1000 + i, "TCP", 5)],
            )

        summary = run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)
        self.assertEqual(summary["total_captures"], 3)
        self.assertEqual(summary["successful_captures"], 3)
        self.assertEqual(summary["total_flows"], 3)
        self.assertEqual(summary["total_packets"], 15)

    def test_05_one_invalid_pcap(self):
        """5. Test that a corrupted PCAP does not crash extraction and is recorded in failed_captures."""
        good_pcap = self.input_dir / "chat" / "chat_good.pcap"
        self._create_synthetic_pcap(
            good_pcap,
            [("10.0.0.1", "10.0.0.2", 4500, 4500, "UDP", 4)],
        )

        bad_pcap = self.input_dir / "chat" / "chat_bad.pcap"
        bad_pcap.write_bytes(b"INVALID_HEADER_DATA_1234567890")

        summary = run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)
        self.assertEqual(summary["total_captures"], 2)
        self.assertEqual(summary["successful_captures"], 1)
        self.assertEqual(summary["failed_captures"], 1)
        self.assertEqual(summary["total_flows"], 1)

        failed_csv = self.output_dir / "failed_captures.csv"
        with failed_csv.open("r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["capture_id"], "chat_bad")
            self.assertEqual(rows[0]["traffic_category"], "chat")

    def test_06_empty_dataset(self):
        """6. Test running extractor on an empty dataset directory."""
        summary = run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)
        self.assertEqual(summary["total_captures"], 0)
        self.assertEqual(summary["successful_captures"], 0)
        self.assertEqual(summary["total_flows"], 0)
        self.assertTrue((self.output_dir / "all_flow_features.csv").exists())
        self.assertTrue((self.output_dir / "all_flow_features.json").exists())
        self.assertTrue((self.output_dir / "processing_report.csv").exists())
        self.assertTrue((self.output_dir / "failed_captures.csv").exists())
        self.assertTrue((self.output_dir / "dataset_summary.json").exists())
        self.assertTrue((self.output_dir / "DATASET_README.md").exists())

    def test_07_flow_id_provenance_handling(self):
        """7. Verify flow_id, dataset_flow_id, source_pcap, and traffic_category."""
        self._create_synthetic_pcap(
            self.input_dir / "chat" / "chat_01.pcap",
            [
                ("10.0.0.1", "10.0.0.2", 4500, 4500, "UDP", 4),
                ("10.0.0.1", "10.0.0.3", 4500, 4500, "UDP", 3),
            ],
        )

        records, report = process_capture(
            self.input_dir / "chat" / "chat_01.pcap",
            self.input_dir,
            use_tshark=False,
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["flow_id"], "flow_1")
        self.assertEqual(records[0]["dataset_flow_id"], "chat_01_flow_1")
        self.assertEqual(records[0]["source_pcap"], "chat/chat_01.pcap")
        self.assertEqual(records[0]["traffic_category"], "chat")

        self.assertEqual(records[1]["flow_id"], "flow_2")
        self.assertEqual(records[1]["dataset_flow_id"], "chat_01_flow_2")

    def test_08_csv_output_schema(self):
        """8. Verify CSV output format, headers, and column count."""
        self._create_synthetic_pcap(
            self.input_dir / "web" / "web_01.pcap",
            [("10.0.0.1", "10.0.0.2", 80, 50000, "TCP", 4)],
        )

        run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)
        csv_path = self.output_dir / "all_flow_features.csv"

        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertEqual(header, DATASET_FIELDNAMES)
            self.assertEqual(len(header), 26)
            row = next(reader)
            self.assertEqual(len(row), 26)

    def test_09_json_output_typing(self):
        """9. Verify JSON output format and data type preservation."""
        self._create_synthetic_pcap(
            self.input_dir / "icmp" / "icmp_01.pcap",
            [("10.0.0.1", "10.0.0.2", None, None, "ICMP", 4)],
        )

        run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)
        json_path = self.output_dir / "all_flow_features.json"

        with json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        obj = data[0]

        # Port for ICMP should be None (JSON null)
        self.assertIsNone(obj["src_port"])
        self.assertIsNone(obj["dst_port"])
        # Integers
        self.assertIsInstance(obj["packet_count"], int)
        self.assertIsInstance(obj["total_bytes"], int)
        # Floats
        self.assertIsInstance(obj["flow_duration_seconds"], float)
        self.assertIsInstance(obj["avg_packet_size"], float)
        # Strings
        self.assertIsInstance(obj["source_pcap"], str)
        self.assertEqual(obj["traffic_category"], "icmp")

    def test_10_csv_json_consistency(self):
        """10. Verify bidirectional consistency between CSV and JSON outputs."""
        self._create_synthetic_pcap(
            self.input_dir / "chat" / "chat_01.pcap",
            [("10.0.0.1", "10.0.0.2", 4500, 4500, "UDP", 4)],
        )
        self._create_synthetic_pcap(
            self.input_dir / "web" / "web_01.pcap",
            [("10.0.0.1", "10.0.0.2", 80, 50000, "TCP", 6)],
        )

        run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)
        csv_path = self.output_dir / "all_flow_features.csv"
        json_path = self.output_dir / "all_flow_features.json"

        is_consistent, errors = validate_csv_json_consistency(csv_path, json_path)
        self.assertTrue(is_consistent, f"Consistency errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_11_failed_capture_reporting(self):
        """11. Verify processing_report.csv and failed_captures.csv logging."""
        self._create_synthetic_pcap(
            self.input_dir / "good" / "good_01.pcap",
            [("10.0.0.1", "10.0.0.2", 80, 5000, "TCP", 2)],
        )
        bad_file = self.input_dir / "bad" / "bad_01.pcap"
        bad_file.parent.mkdir(parents=True, exist_ok=True)
        bad_file.write_bytes(b"CORRUPT")

        run_dataset_extraction(self.input_dir, self.output_dir, use_tshark=False)

        proc_report = self.output_dir / "processing_report.csv"
        with proc_report.open("r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            statuses = {r["capture_id"]: r["status"] for r in rows}
            self.assertEqual(statuses["good_01"], "SUCCESS")
            self.assertEqual(statuses["bad_01"], "FAILED")

    def test_12_category_summary(self):
        """12. Verify category summary calculation."""
        reports = [
            {"traffic_category": "chat", "status": "SUCCESS", "flow_count": 2, "packet_count": 20},
            {"traffic_category": "chat", "status": "SUCCESS", "flow_count": 1, "packet_count": 10},
            {"traffic_category": "video", "status": "SUCCESS", "flow_count": 1, "packet_count": 50},
            {"traffic_category": "video", "status": "FAILED", "flow_count": 0, "packet_count": 0},
        ]
        records = [
            {"traffic_category": "chat", "total_bytes": 1000},
            {"traffic_category": "chat", "total_bytes": 500},
            {"traffic_category": "video", "total_bytes": 5000},
        ]

        summary = compute_category_summary(reports, records)
        self.assertEqual(summary["chat"]["capture_count"], 2)
        self.assertEqual(summary["chat"]["successful_capture_count"], 2)
        self.assertEqual(summary["chat"]["failed_capture_count"], 0)
        self.assertEqual(summary["chat"]["flow_count"], 3)
        self.assertEqual(summary["chat"]["packet_count"], 30)
        self.assertEqual(summary["chat"]["total_bytes"], 1500)

        self.assertEqual(summary["video"]["capture_count"], 2)
        self.assertEqual(summary["video"]["successful_capture_count"], 1)
        self.assertEqual(summary["video"]["failed_capture_count"], 1)
        self.assertEqual(summary["video"]["flow_count"], 1)
        self.assertEqual(summary["video"]["packet_count"], 50)
        self.assertEqual(summary["video"]["total_bytes"], 5000)


if __name__ == "__main__":
    unittest.main()
