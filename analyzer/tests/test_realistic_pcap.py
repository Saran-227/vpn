import unittest
from pathlib import Path

from analyzer.feature_extractor.feature_extractor import (
    extract_features_from_packets,
)
from analyzer.feature_extractor.packet_reader import read_pcap


class TestRealisticPCAP(unittest.TestCase):
    PCAP = Path("analyzer/sample_data/realistic_mixed.pcap")

    def test_realistic_pcap_packet_count(self):
        packets = list(read_pcap(self.PCAP))

        self.assertEqual(len(packets), 15)

    def test_realistic_pcap_flow_count(self):
        packets = list(read_pcap(self.PCAP))
        features = extract_features_from_packets(packets)

        self.assertEqual(len(features), 4)

    def test_realistic_protocols(self):
        packets = list(read_pcap(self.PCAP))
        features = extract_features_from_packets(packets)

        protocols = [feature.protocol for feature in features]

        self.assertEqual(
            protocols,
            ["TCP", "UDP", "ICMP", "ESP"],
        )

    def test_realistic_packet_counts(self):
        packets = list(read_pcap(self.PCAP))
        features = extract_features_from_packets(packets)

        packet_counts = [feature.packet_count for feature in features]

        self.assertEqual(packet_counts, [4, 4, 3, 4])

    def test_realistic_total_bytes(self):
        packets = list(read_pcap(self.PCAP))
        features = extract_features_from_packets(packets)

        total_bytes = [feature.total_bytes for feature in features]

        self.assertEqual(total_bytes, [2960, 1412, 340, 3262])

    def test_realistic_rates_are_positive(self):
        packets = list(read_pcap(self.PCAP))
        features = extract_features_from_packets(packets)

        for feature in features:
            self.assertGreater(feature.flow_duration_seconds, 0.0)
            self.assertGreater(feature.packets_per_second, 0.0)
            self.assertGreater(feature.bytes_per_second, 0.0)

    def test_realistic_packet_size_variation(self):
        packets = list(read_pcap(self.PCAP))
        features = extract_features_from_packets(packets)

        for feature in features:
            self.assertGreaterEqual(feature.max_packet_size, feature.min_packet_size)
            self.assertGreaterEqual(feature.packet_size_std, 0.0)


if __name__ == "__main__":
    unittest.main()
