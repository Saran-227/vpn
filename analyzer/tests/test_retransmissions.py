import unittest

from analyzer.feature_extractor.feature_extractor import extract_flow_features
from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.packet_reader import PacketRecord


class TestRetransmissions(unittest.TestCase):

    def test_duplicate_packets_are_preserved(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=200,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="UDP",
                src_port=500,
                dst_port=500,
            ),
            PacketRecord(
                timestamp=1.1,
                length=200,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="UDP",
                src_port=500,
                dst_port=500,
            ),
            PacketRecord(
                timestamp=1.2,
                length=200,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="UDP",
                src_port=500,
                dst_port=500,
            ),
            PacketRecord(
                timestamp=1.3,
                length=180,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                protocol="UDP",
                src_port=500,
                dst_port=500,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        features = extract_flow_features(flows[0], packets)

        self.assertEqual(features.packet_count, 4)
        self.assertEqual(features.total_bytes, 780)

        self.assertEqual(
            features.forward_packet_count + features.backward_packet_count,
            4,
        )

        self.assertEqual(
            features.forward_bytes + features.backward_bytes,
            780,
        )

        self.assertTrue(features.flow_duration_seconds > 0)
        self.assertTrue(features.packets_per_second > 0)
        self.assertTrue(features.bytes_per_second > 0)


if __name__ == "__main__":
    unittest.main()
