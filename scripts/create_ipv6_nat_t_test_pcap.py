from scapy.all import Ether, IPv6, UDP, Raw, wrpcap


packets = [
    Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    ) / IPv6(
        src="2001:db8::1",
        dst="2001:db8::2",
    ) / UDP(
        sport=4500,
        dport=4500,
    ) / Raw(
        b"\x00" * 140
    ),

    Ether(
        src="02:00:00:00:00:02",
        dst="02:00:00:00:00:01",
    ) / IPv6(
        src="2001:db8::2",
        dst="2001:db8::1",
    ) / UDP(
        sport=4500,
        dport=4500,
    ) / Raw(
        b"\x00" * 180
    ),
]


wrpcap(
    "analyzer/sample_data/ipv6_nat_t_test.pcap",
    packets,
)

print("Created analyzer/sample_data/ipv6_nat_t_test.pcap")
