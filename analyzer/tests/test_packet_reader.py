import unittest
from pathlib import Path

from analyzer.feature_extractor.packet_reader import read_pcap


class TestPacketReader(unittest.TestCase):

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

    IPV6_PCAP = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "ipv6_test.pcap"
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

    NAT_T_PCAP = (
        Path(__file__).resolve().parents[1]
        / "sample_data"
        / "nat_t_test.pcap"
    )

    def test_basic_pcap_packet_count(self):
        packets = list(read_pcap(self.BASIC_PCAP))
        self.assertEqual(len(packets), 5)

    def test_tcp_packet(self):
        packets = list(read_pcap(self.BASIC_PCAP))

        tcp_packets = [
            packet
            for packet in packets
            if packet.protocol == "TCP"
        ]

        self.assertEqual(len(tcp_packets), 2)

        packet = next(
            packet
            for packet in tcp_packets
            if packet.src_port == 12345
            and packet.dst_port == 443
        )

        self.assertEqual(packet.src_ip, "10.0.0.1")
        self.assertEqual(packet.dst_ip, "10.0.0.2")

    def test_udp_packet(self):
        packets = list(read_pcap(self.BASIC_PCAP))

        udp_packets = [
            packet
            for packet in packets
            if packet.protocol == "UDP"
        ]

        self.assertEqual(len(udp_packets), 2)

        packet = next(
            packet
            for packet in udp_packets
            if packet.src_port == 50000
            and packet.dst_port == 50001
        )

        self.assertEqual(packet.src_ip, "10.0.0.1")
        self.assertEqual(packet.dst_ip, "10.0.0.2")

    def test_icmp_packet_has_no_ports(self):
        packets = list(read_pcap(self.BASIC_PCAP))

        icmp_packets = [
            packet
            for packet in packets
            if packet.protocol == "ICMP"
        ]

        self.assertEqual(len(icmp_packets), 1)

        packet = icmp_packets[0]

        self.assertEqual(packet.src_ip, "10.0.0.1")
        self.assertEqual(packet.dst_ip, "10.0.0.2")
        self.assertIsNone(packet.src_port)
        self.assertIsNone(packet.dst_port)

    def test_esp_packet_has_no_ports(self):
        packets = list(read_pcap(self.IPSEC_PCAP))

        self.assertEqual(len(packets), 3)

        packet = next(
            packet
            for packet in packets
            if packet.src_ip == "192.168.1.10"
            and packet.dst_ip == "192.168.1.20"
        )

        self.assertEqual(packet.protocol, "ESP")
        self.assertIsNone(packet.src_port)
        self.assertIsNone(packet.dst_port)

    def test_missing_pcap_raises_error(self):
        missing_path = (
            Path(__file__).resolve().parents[1]
            / "sample_data"
            / "does_not_exist.pcap"
        )

        with self.assertRaises(FileNotFoundError):
            list(read_pcap(missing_path))

    def test_ipv6_tcp_packet(self):
        packets = list(read_pcap(self.IPV6_PCAP))

        self.assertEqual(len(packets), 2)

        packet = packets[0]

        self.assertEqual(packet.src_ip, "2001:db8::1")
        self.assertEqual(packet.dst_ip, "2001:db8::2")
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.src_port, 50000)
        self.assertEqual(packet.dst_port, 443)

    def test_ipv6_esp_packet(self):
        packets = list(read_pcap(self.IPV6_ESP_PCAP))

        self.assertEqual(len(packets), 2)

        packet = packets[0]

        self.assertEqual(packet.src_ip, "2001:db8::1")
        self.assertEqual(packet.dst_ip, "2001:db8::2")
        self.assertEqual(packet.protocol, "ESP")
        self.assertIsNone(packet.src_port)
        self.assertIsNone(packet.dst_port)

    def test_ike_udp_500_packet(self):
        packets = list(read_pcap(self.IKE_PCAP))

        self.assertEqual(len(packets), 2)

        packet = packets[0]

        self.assertEqual(packet.src_ip, "192.0.2.1")
        self.assertEqual(packet.dst_ip, "192.0.2.2")
        self.assertEqual(packet.protocol, "UDP")
        self.assertEqual(packet.src_port, 500)
        self.assertEqual(packet.dst_port, 500)

    def test_ipv6_nat_t_udp_4500_packet(self):
        pcap_path = (
            Path(__file__).resolve().parents[1]
            / "sample_data"
            / "ipv6_nat_t_test.pcap"
        )

        packets = list(read_pcap(pcap_path))

        self.assertEqual(len(packets), 2)

        packet = packets[0]

        self.assertEqual(packet.src_ip, "2001:db8::1")
        self.assertEqual(packet.dst_ip, "2001:db8::2")
        self.assertEqual(packet.protocol, "UDP")
        self.assertEqual(packet.src_port, 4500)
        self.assertEqual(packet.dst_port, 4500)
        self.assertEqual(packet.length, 202)

    def test_nat_t_udp_4500_packet(self):
        packets = list(read_pcap(self.NAT_T_PCAP))

        self.assertEqual(len(packets), 2)

        packet = packets[0]

        self.assertEqual(packet.src_ip, "192.0.2.1")
        self.assertEqual(packet.dst_ip, "192.0.2.2")
        self.assertEqual(packet.protocol, "UDP")
        self.assertEqual(packet.src_port, 4500)
        self.assertEqual(packet.dst_port, 4500)
        self.assertEqual(packet.length, 182)


if __name__ == "__main__":
    unittest.main()
