from scapy.all import ESP, ICMP, IP, Raw, TCP, UDP, wrpcap


def add_timestamps(packets, start_time=1_000_000.0):
    timestamp = start_time

    for index, packet in enumerate(packets):
        packet.time = timestamp

        if index % 4 == 0:
            timestamp += 0.020
        elif index % 4 == 1:
            timestamp += 0.035
        elif index % 4 == 2:
            timestamp += 0.015
        else:
            timestamp += 0.050

    return packets


def main() -> None:
    packets = []

    tcp_packets = [
        IP(src="10.10.0.1", dst="10.10.0.2")
        / TCP(sport=40000, dport=443, flags="PA")
        / Raw(load=b"A" * 500),

        IP(src="10.10.0.2", dst="10.10.0.1")
        / TCP(sport=443, dport=40000, flags="PA")
        / Raw(load=b"B" * 1200),

        IP(src="10.10.0.1", dst="10.10.0.2")
        / TCP(sport=40000, dport=443, flags="PA")
        / Raw(load=b"C" * 800),

        IP(src="10.10.0.2", dst="10.10.0.1")
        / TCP(sport=443, dport=40000, flags="PA")
        / Raw(load=b"D" * 300),
    ]

    udp_packets = [
        IP(src="10.10.0.3", dst="10.10.0.4")
        / UDP(sport=50000, dport=50001)
        / Raw(load=b"E" * 200),

        IP(src="10.10.0.4", dst="10.10.0.3")
        / UDP(sport=50001, dport=50000)
        / Raw(load=b"F" * 350),

        IP(src="10.10.0.3", dst="10.10.0.4")
        / UDP(sport=50000, dport=50001)
        / Raw(load=b"G" * 600),

        IP(src="10.10.0.4", dst="10.10.0.3")
        / UDP(sport=50001, dport=50000)
        / Raw(load=b"H" * 150),
    ]

    icmp_packets = [
        IP(src="10.10.0.5", dst="10.10.0.6")
        / ICMP()
        / Raw(load=b"I" * 64),

        IP(src="10.10.0.6", dst="10.10.0.5")
        / ICMP(type="echo-reply")
        / Raw(load=b"J" * 64),

        IP(src="10.10.0.5", dst="10.10.0.6")
        / ICMP()
        / Raw(load=b"K" * 128),
    ]

    esp_packets = [
        IP(src="192.168.100.10", dst="192.168.100.20")
        / ESP(spi=0x1001, seq=1)
        / Raw(load=b"L" * 700),

        IP(src="192.168.100.20", dst="192.168.100.10")
        / ESP(spi=0x2001, seq=1)
        / Raw(load=b"M" * 900),

        IP(src="192.168.100.10", dst="192.168.100.20")
        / ESP(spi=0x1001, seq=2)
        / Raw(load=b"N" * 450),

        IP(src="192.168.100.20", dst="192.168.100.10")
        / ESP(spi=0x2001, seq=2)
        / Raw(load=b"O" * 1100),
    ]

    packets.extend(tcp_packets)
    packets.extend(udp_packets)
    packets.extend(icmp_packets)
    packets.extend(esp_packets)

    packets = add_timestamps(packets)

    output_path = "analyzer/sample_data/realistic_mixed.pcap"

    wrpcap(output_path, packets)

    print(f"Created: {output_path}")
    print(f"Packet count: {len(packets)}")


if __name__ == "__main__":
    main()
