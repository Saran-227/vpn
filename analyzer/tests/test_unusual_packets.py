import unittest

from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.packet_reader import PacketRecord


class TestUnusualPackets(unittest.TestCase):

    def test_missing_ports_and_non_ip_packets_are_safe(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=60,
                src_ip=None,
                dst_ip=None,
                protocol="ETHERNET",
                src_port=None,
                dst_port=None,
            ),
            PacketRecord(
                timestamp=1.1,
                length=100,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="ICMP",
                src_port=None,
                dst_port=None,
            ),
            PacketRecord(
                timestamp=1.2,
                length=120,
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                protocol="ESP",
                src_port=None,
                dst_port=None,
            ),
            PacketRecord(
                timestamp=1.3,
                length=140,
                src_ip="2001:db8::1",
                dst_ip="2001:db8::2",
                protocol="ESP",
                src_port=None,
                dst_port=None,
            ),
            PacketRecord(
                timestamp=1.4,
                length=200,
                src_ip="10.0.0.3",
                dst_ip="10.0.0.4",
                protocol="TCP",
                src_port=50000,
                dst_port=443,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 4)

        protocols = sorted(flow.key.protocol for flow in flows)

        self.assertEqual(
            protocols,
            ["ESP", "ESP", "ICMP", "TCP"],
        )

        for flow in flows:
            self.assertIsNotNone(flow.key.endpoint_a_ip)
            self.assertIsNotNone(flow.key.endpoint_b_ip)


if __name__ == "__main__":
    unittest.main()
