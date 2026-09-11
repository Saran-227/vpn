from scapy.all import Ether, IPv6, TCP, wrpcap

packets = [
    Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    ) / IPv6(
        src="2001:db8::1",
        dst="2001:db8::2",
    ) / TCP(
        sport=50000,
        dport=443,
        flags="S",
    ),

    Ether(
        src="02:00:00:00:00:02",
        dst="02:00:00:00:00:01",
    ) / IPv6(
        src="2001:db8::2",
        dst="2001:db8::1",
    ) / TCP(
        sport=443,
        dport=50000,
        flags="SA",
    ),
]

wrpcap(
    "analyzer/sample_data/ipv6_test.pcap",
    packets,
)

print("Created analyzer/sample_data/ipv6_test.pcap")
