import unittest
from pathlib import Path

from scapy.all import IP, UDP, Raw, fragment, wrpcap

from analyzer.feature_extractor.packet_reader import read_pcap
from analyzer.feature_extractor.flow_builder import build_flows


class TestRealFragmentation(unittest.TestCase):
    def test_ipv4_fragmented_pcap_is_read_safely(self):
        pcap_path = Path("analyzer/sample_data/fragmented_ipv4_test.pcap")

        packet = (
            IP(src="10.10.0.1", dst="10.10.0.2")
            / UDP(sport=5000, dport=5001)
            / Raw(load=b"A" * 2000)
        )

        fragments = fragment(packet, fragsize=600)
        wrpcap(str(pcap_path), fragments)

        packets = list(read_pcap(pcap_path))

        self.assertGreater(len(packets), 1)

        for packet_record in packets:
            self.assertEqual(packet_record.src_ip, "10.10.0.1")
            self.assertEqual(packet_record.dst_ip, "10.10.0.2")
            self.assertGreater(packet_record.length, 0)

        flows = build_flows(packets)

        self.assertGreaterEqual(len(flows), 1)


if __name__ == "__main__":
    unittest.main()
