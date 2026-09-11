import csv
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from analyzer.feature_extractor.exporter import export_features_to_csv
from analyzer.feature_extractor.feature_extractor import extract_features_from_packets
from analyzer.feature_extractor.packet_reader import read_pcap


class TestExporter(unittest.TestCase):
    BASIC_PCAP = Path("analyzer/sample_data/basic_test.pcap")

    EXPECTED_COLUMNS = [
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

    def test_csv_export(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        features = extract_features_from_packets(packets)

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "features.csv"

            export_features_to_csv(features, output_path)

            self.assertTrue(output_path.exists())

            with output_path.open(
                "r",
                newline="",
                encoding="utf-8",
            ) as file:
                rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 3)

    def test_csv_columns_are_stable(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        features = extract_features_from_packets(packets)

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "features.csv"

            export_features_to_csv(features, output_path)

            with output_path.open(
                "r",
                newline="",
                encoding="utf-8",
            ) as file:
                reader = csv.reader(file)
                header = next(reader)

        self.assertEqual(header, self.EXPECTED_COLUMNS)

    def test_icmp_ports_are_empty(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        features = extract_features_from_packets(packets)

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "features.csv"

            export_features_to_csv(features, output_path)

            with output_path.open(
                "r",
                newline="",
                encoding="utf-8",
            ) as file:
                rows = list(csv.DictReader(file))

        icmp_row = next(row for row in rows if row["protocol"] == "ICMP")

        self.assertEqual(icmp_row["src_port"], "")
        self.assertEqual(icmp_row["dst_port"], "")

    def test_no_ml_label_column(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        features = extract_features_from_packets(packets)

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "features.csv"

            export_features_to_csv(features, output_path)

            with output_path.open(
                "r",
                newline="",
                encoding="utf-8",
            ) as file:
                header = next(csv.reader(file))

        self.assertNotIn("traffic_type", header)
        self.assertNotIn("label", header)
        self.assertNotIn("prediction", header)


if __name__ == "__main__":
    unittest.main()
