from scapy.all import ICMP, IP, TCP, UDP, Raw, wrpcap


def main() -> None:
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=443, flags="S"),

        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=443, dport=12345, flags="SA"),

        IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=50000, dport=50001)
        / Raw(load=b"test udp payload"),

        IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=50001, dport=50000)
        / Raw(load=b"udp response"),

        IP(src="10.0.0.1", dst="10.0.0.2")
        / ICMP(),
    ]

    output_path = "analyzer/sample_data/basic_test.pcap"

    wrpcap(output_path, packets)

    print(f"Created test PCAP: {output_path}")
    print(f"Packet count: {len(packets)}")


if __name__ == "__main__":
    main()
