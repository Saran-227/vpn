from scapy.all import ESP, IP, Raw, wrpcap


def main() -> None:
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / ESP(spi=0x1001, seq=1)
        / Raw(load=b"encrypted-payload-1"),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / ESP(spi=0x2001, seq=1)
        / Raw(load=b"encrypted-payload-2"),

        IP(src="192.168.1.10", dst="192.168.1.20")
        / ESP(spi=0x1001, seq=2)
        / Raw(load=b"encrypted-payload-3"),
    ]

    output_path = "analyzer/sample_data/ipsec_test.pcap"

    wrpcap(output_path, packets)

    print(f"Created test PCAP: {output_path}")
    print(f"Packet count: {len(packets)}")


if __name__ == "__main__":
    main()

