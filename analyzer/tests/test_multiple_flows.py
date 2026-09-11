import unittest

from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.packet_reader import PacketRecord


class TestMultipleFlows(unittest.TestCase):

    def test_multiple_concurrent_flows_are_separated(self):
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
                timestamp=1.01,
                length=200,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="UDP",
                src_port=40000,
                dst_port=4500,
            ),
            PacketRecord(
                timestamp=1.02,
                length=150,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                protocol="TCP",
                src_port=443,
                dst_port=50000,
            ),
            PacketRecord(
                timestamp=1.03,
                length=250,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="TCP",
                src_port=50001,
                dst_port=443,
            ),
            PacketRecord(
                timestamp=1.04,
                length=300,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                protocol="UDP",
                src_port=4500,
                dst_port=40000,
            ),
            PacketRecord(
                timestamp=1.05,
                length=350,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                protocol="TCP",
                src_port=443,
                dst_port=50001,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 3)

        flow_signatures = {
            (
                flow.key.protocol,
                flow.key.endpoint_a_ip,
                flow.key.endpoint_a_port,
                flow.key.endpoint_b_ip,
                flow.key.endpoint_b_port,
            )
            for flow in flows
        }

        self.assertEqual(
            len(flow_signatures),
            3,
        )

        protocols = sorted(flow.key.protocol for flow in flows)

        self.assertEqual(
            protocols,
            ["TCP", "TCP", "UDP"],
        )


if __name__ == "__main__":
    unittest.main()
