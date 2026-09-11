import unittest

from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.packet_reader import PacketRecord


class TestFragmentation(unittest.TestCase):

    def test_ipv4_fragments_are_safe(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=600,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="IP",
                src_port=None,
                dst_port=None,
            ),
            PacketRecord(
                timestamp=1.01,
                length=600,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="IP",
                src_port=None,
                dst_port=None,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].key.protocol, "IP")
        self.assertEqual(flows[0].forward_packet_count, 2)
        self.assertEqual(flows[0].backward_packet_count, 0)
        self.assertEqual(flows[0].forward_bytes, 1200)


if __name__ == "__main__":
    unittest.main()
