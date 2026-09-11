import unittest
from pathlib import Path

from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.packet_reader import PacketRecord, read_pcap


class TestFlowBuilder(unittest.TestCase):

    BASIC_PCAP = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "basic_test.pcap"
    )

    IPSEC_PCAP = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "ipsec_test.pcap"
    )

    IPV6_ESP_PCAP = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "ipv6_esp_test.pcap"
    )

    IKE_PCAP = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "ike_test.pcap"
    )

    def test_basic_pcap_flow_count(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        flows = build_flows(packets)
        self.assertEqual(len(flows), 3)

    def test_tcp_bidirectional_flow(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=100,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.20",
                protocol="TCP",
                src_port=50000,
                dst_port=443,
            ),
            PacketRecord(
                timestamp=1.1,
                length=150,
                src_ip="192.168.1.20",
                dst_ip="192.168.1.10",
                protocol="TCP",
                src_port=443,
                dst_port=50000,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_bytes, 100)
        self.assertEqual(flow.backward_bytes, 150)

    def test_udp_bidirectional_flow(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=80,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="UDP",
                src_port=40000,
                dst_port=53,
            ),
            PacketRecord(
                timestamp=1.2,
                length=120,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                protocol="UDP",
                src_port=53,
                dst_port=40000,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_bytes, 80)
        self.assertEqual(flow.backward_bytes, 120)

    def test_icmp_flow(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=100,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="ICMP",
                src_port=None,
                dst_port=None,
            ),
            PacketRecord(
                timestamp=1.1,
                length=120,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                protocol="ICMP",
                src_port=None,
                dst_port=None,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.key.protocol, "ICMP")
        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)

    def test_esp_bidirectional_flow(self):
        packets = list(read_pcap(self.IPSEC_PCAP))

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        esp_flow = flows[0]

        self.assertEqual(esp_flow.key.protocol, "ESP")
        self.assertEqual(esp_flow.forward_packet_count, 2)
        self.assertEqual(esp_flow.backward_packet_count, 1)
        self.assertEqual(esp_flow.forward_bytes, 94)
        self.assertEqual(esp_flow.backward_bytes, 47)

    def test_empty_packet_list(self):
        flows = build_flows([])
        self.assertEqual(flows, [])

    def test_non_ip_packet_is_not_used_as_flow(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=60,
                src_ip=None,
                dst_ip=None,
                protocol="ETHERNET",
                src_port=None,
                dst_port=None,
            )
        ]

        flows = build_flows(packets)

        self.assertEqual(flows, [])

    def test_ipv6_bidirectional_flow(self):
        packets = [
            PacketRecord(
                timestamp=1.0,
                length=100,
                src_ip="2001:db8::1",
                dst_ip="2001:db8::2",
                protocol="TCP",
                src_port=50000,
                dst_port=443,
            ),
            PacketRecord(
                timestamp=1.1,
                length=150,
                src_ip="2001:db8::2",
                dst_ip="2001:db8::1",
                protocol="TCP",
                src_port=443,
                dst_port=50000,
            ),
        ]

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_bytes, 100)
        self.assertEqual(flow.backward_bytes, 150)

    def test_ipv6_esp_bidirectional_flow(self):
        packets = list(read_pcap(self.IPV6_ESP_PCAP))

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.key.protocol, "ESP")
        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_bytes, 94)
        self.assertEqual(flow.backward_bytes, 110)

    def test_ipv6_nat_t_udp_4500_bidirectional_flow(self):
        pcap_path = (
            Path(__file__).resolve().parents[1]
            / "sample_data"
            / "ipv6_nat_t_test.pcap"
        )

        packets = list(read_pcap(pcap_path))

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.key.protocol, "UDP")
        self.assertEqual(flow.key.endpoint_a_ip, "2001:db8::1")
        self.assertEqual(flow.key.endpoint_b_ip, "2001:db8::2")
        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_bytes, 202)
        self.assertEqual(flow.backward_bytes, 242)

    def test_nat_t_udp_4500_bidirectional_flow(self):
        pcap_path = (
            Path(__file__).resolve().parents[1]
            / "sample_data"
            / "nat_t_test.pcap"
        )

        packets = list(read_pcap(pcap_path))

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.key.protocol, "UDP")
        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_bytes, 182)
        self.assertEqual(flow.backward_bytes, 222)

    def test_ike_udp_500_bidirectional_flow(self):
        packets = list(read_pcap(self.IKE_PCAP))

        flows = build_flows(packets)

        self.assertEqual(len(flows), 1)

        flow = flows[0]

        self.assertEqual(flow.key.protocol, "UDP")
        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_bytes, 170)
        self.assertEqual(flow.backward_bytes, 202)


if __name__ == "__main__":
    unittest.main()
