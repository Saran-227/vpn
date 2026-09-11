import unittest

from analyzer.feature_extractor.feature_extractor import extract_flow_features
from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.packet_reader import PacketRecord


class TestFlowEdgeCases(unittest.TestCase):

    def test_one_way_flow(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=100,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="TCP",
                src_port=50000,
                dst_port=443,
            ),
            PacketRecord(
                timestamp=1.1,
                length=200,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="TCP",
                src_port=50000,
                dst_port=443,
            ),
            PacketRecord(
                timestamp=1.2,
                length=150,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="TCP",
                src_port=50000,
                dst_port=443,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        features = extract_flow_features(flows[0], packets)

        self.assertEqual(features.packet_count, 3)
        self.assertEqual(features.forward_packet_count, 3)
        self.assertEqual(features.backward_packet_count, 0)

        self.assertEqual(features.forward_bytes, 450)
        self.assertEqual(features.backward_bytes, 0)

        self.assertGreater(features.flow_duration_seconds, 0)
        self.assertGreater(features.packets_per_second, 0)
        self.assertGreater(features.bytes_per_second, 0)

    def test_single_packet_flow(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=100,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="UDP",
                src_port=50000,
                dst_port=4500,
            )
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        features = extract_flow_features(flows[0], packets)

        self.assertEqual(features.packet_count, 1)
        self.assertEqual(features.total_bytes, 100)

        self.assertEqual(features.flow_duration_seconds, 0.0)

        self.assertEqual(features.forward_packet_count, 1)
        self.assertEqual(features.backward_packet_count, 0)

        self.assertEqual(features.forward_bytes, 100)
        self.assertEqual(features.backward_bytes, 0)

        self.assertEqual(features.packets_per_second, 0.0)
        self.assertEqual(features.bytes_per_second, 0.0)

        self.assertEqual(features.min_inter_arrival_seconds, 0.0)
        self.assertEqual(features.max_inter_arrival_seconds, 0.0)
        self.assertEqual(features.avg_inter_arrival_seconds, 0.0)
        self.assertEqual(features.inter_arrival_std, 0.0)


if __name__ == "__main__":
    unittest.main()
