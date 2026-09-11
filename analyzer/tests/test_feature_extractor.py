import math
import unittest
from pathlib import Path

from analyzer.feature_extractor.feature_extractor import extract_flow_features
from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.packet_reader import read_pcap


class TestFeatureExtractor(unittest.TestCase):
    BASIC_PCAP = Path("analyzer/sample_data/basic_test.pcap")
    IPSEC_PCAP = Path("analyzer/sample_data/ipsec_test.pcap")

    def test_tcp_features(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        flows = build_flows(packets)

        tcp_flow = next(flow for flow in flows if flow.key.protocol == "TCP")
        features = extract_flow_features(tcp_flow, packets)

        self.assertEqual(features.packet_count, 2)
        self.assertEqual(features.total_bytes, 80)
        self.assertEqual(features.min_packet_size, 40)
        self.assertEqual(features.max_packet_size, 40)
        self.assertEqual(features.avg_packet_size, 40.0)
        self.assertEqual(features.packet_size_std, 0.0)
        self.assertEqual(features.forward_packet_count, 1)
        self.assertEqual(features.backward_packet_count, 1)
        self.assertEqual(features.forward_bytes, 40)
        self.assertEqual(features.backward_bytes, 40)

    def test_udp_features(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        flows = build_flows(packets)

        udp_flow = next(flow for flow in flows if flow.key.protocol == "UDP")
        features = extract_flow_features(udp_flow, packets)

        self.assertEqual(features.packet_count, 2)
        self.assertEqual(features.total_bytes, 84)
        self.assertEqual(features.min_packet_size, 40)
        self.assertEqual(features.max_packet_size, 44)
        self.assertEqual(features.avg_packet_size, 42.0)
        self.assertEqual(features.packet_size_std, 2.0)

    def test_icmp_single_packet(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        flows = build_flows(packets)

        icmp_flow = next(flow for flow in flows if flow.key.protocol == "ICMP")
        features = extract_flow_features(icmp_flow, packets)

        self.assertEqual(features.packet_count, 1)
        self.assertEqual(features.total_bytes, 28)
        self.assertEqual(features.flow_duration_seconds, 0.0)
        self.assertEqual(features.packets_per_second, 0.0)
        self.assertEqual(features.bytes_per_second, 0.0)
        self.assertEqual(features.avg_inter_arrival_seconds, 0.0)

    def test_esp_features(self):
        packets = list(read_pcap(self.IPSEC_PCAP))
        flows = build_flows(packets)

        esp_flow = flows[0]
        features = extract_flow_features(esp_flow, packets)

        self.assertEqual(features.packet_count, 3)
        self.assertEqual(features.total_bytes, 141)
        self.assertEqual(features.min_packet_size, 47)
        self.assertEqual(features.max_packet_size, 47)
        self.assertEqual(features.avg_packet_size, 47.0)
        self.assertEqual(features.packet_size_std, 0.0)
        self.assertEqual(features.forward_packet_count, 2)
        self.assertEqual(features.backward_packet_count, 1)
        self.assertEqual(features.forward_bytes, 94)
        self.assertEqual(features.backward_bytes, 47)

    def test_inter_arrival_statistics(self):
        packets = list(read_pcap(self.IPSEC_PCAP))
        flows = build_flows(packets)

        features = extract_flow_features(flows[0], packets)

        self.assertGreater(features.flow_duration_seconds, 0.0)
        self.assertGreater(features.min_inter_arrival_seconds, 0.0)
        self.assertGreater(features.max_inter_arrival_seconds, 0.0)
        self.assertGreater(features.avg_inter_arrival_seconds, 0.0)
        self.assertGreaterEqual(features.inter_arrival_std, 0.0)

    def test_missing_flow_packets(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        flows = build_flows(packets)

        with self.assertRaises(ValueError):
            extract_flow_features(flows[0], [])

    def test_feature_values_are_finite(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        flows = build_flows(packets)

        for flow in flows:
            features = extract_flow_features(flow, packets)

            numeric_values = [
                features.flow_duration_seconds,
                features.avg_packet_size,
                features.packet_size_std,
                features.packets_per_second,
                features.bytes_per_second,
                features.min_inter_arrival_seconds,
                features.max_inter_arrival_seconds,
                features.avg_inter_arrival_seconds,
                features.inter_arrival_std,
            ]

            for value in numeric_values:
                self.assertTrue(math.isfinite(value))


if __name__ == "__main__":
    unittest.main()
